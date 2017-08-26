#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef ONDEVICE
#include <sys/utsname.h>
#endif

#include "offsets.h"
#include "macho.h"
#include "filetools.h"
#include "keys.h"
#include "kcache_export.h"

#ifdef ONDEVICE
#define OFFSETSJ_PATH "/untether/offsets.json"
#else
#define OFFSETSJ_PATH "offsets.json"
#endif

int process_kcache(const char *filename);
int use_supplies;
char *supplies_url;

int main(int argc, char* argv[]) {
  char *idevice = NULL;
  char *iosvers = NULL;
  char *path = NULL;
  char *wd = NULL;
  int is_decrypted = 0;
  use_supplies = 0;
  supplies_url = NULL;

#ifdef ONDEVICE
  wd = "/tmp";
  path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";

  struct utsname systemInfo;
  uname(&systemInfo);
  idevice = systemInfo.machine;

  // I'm too lazy to implement my own sw_vers
  FILE *fp = popen("sw_vers", "r");
  if (fp == NULL) {
    fprintf(stderr, "FAIL: Cant run sw_vers!\n");
    return 1;
  }

  char buf[128] = { 0 };
  while (fgets(buf, sizeof(buf)-1, fp) != NULL) {
    if (strstr(buf, "BuildVersion:") != NULL) {
      iosvers = buf + strlen("BuidVersion:");
      while (!(*iosvers >= '0' && *iosvers <= '9') || (*iosvers >= 'A' && *iosvers <= 'Z'))
        iosvers++;

      
      char *iosvers_end = iosvers;
      while((*iosvers_end >= '0' && *iosvers_end <= '9') || (*iosvers_end >= 'A' && *iosvers_end <= 'Z')) 
        iosvers_end++;

      *iosvers_end = '\0';

      break;
    }
  }
  pclose(fp);

  if (argc == 2 && (strcmp(argv[1], "wall") == 0)) {
    use_supplies = 1;
    fprintf(stderr, "INFO: Will use wall.supplies since ran with `wall` option\n");
  }

#else

  wd = ".";
  if (argc != 3 && argc != 4) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s idevice-iosvers enc_kcache [wall]\n", argv[0]);
    fprintf(stderr, "OR\n");
    fprintf(stderr, "%s decr dec_kcache\n", argv[0]);
    return 1;
  }

  if (strcmp(argv[1], "decr") == 0) {
    is_decrypted = 1;
  } else {
    char *_pos = strchr(argv[1], '-');
    if (_pos == NULL) {
      fprintf(stderr, "FAIL: Invalid idevice-iosves\n");
      return 1;
    }

    idevice = argv[1];
    *_pos = '\0';
    iosvers = _pos + 1;
  }

  if (argc == 4 && (strcmp(argv[3], "wall") == 0)) {
    if (!is_decrypted) {
      use_supplies = 1;
      fprintf(stderr, "INFO: Will use wall.supplies since ran with `wall` option\n");
    } else {
      fprintf(stderr, "FAIL: Cant use wall.supplies with decr\n");
      return 1;
    }
  }

  path = argv[2];

#endif

  if (!is_decrypted) {
    fprintf(stderr, "INFO: Detected %s on %s\n", idevice, iosvers);
    struct devinfo *info;
    if (iosvers[0] == '9') {// 9.X[.Y]
      info = get_dev_iosv(idevice, iosvers);
    } else {
      info = get_dev_build(idevice, iosvers); 
    }

    if (info == NULL) {
      fprintf(stderr, "FAIL: Cant find info about this device/os\n");
      return 1;
    }

    fprintf(stderr, "INFO: Found info about %s on %s\n", info->idevice, info->build);

    fprintf(stderr, "INFO: Trying to decrypt kcache\n");

    // OpenSSL modies IV, and if we pass IV from R/O memory we'll get bus error
    unsigned char *iv_copy = malloc(16 * sizeof(unsigned char));
    memcpy(iv_copy, info->iv, 16 * sizeof(unsigned char));

    // it runs chdir(wd) and writes to kernelcache.bin
    if (kcache_decrypt(path, wd, iv_copy, (unsigned char*)info->key)) { 
      fprintf(stderr, "FAIL: Failed to decrypt kcache!\n");
      return 1;
    }

    free(iv_copy);

    path = "kernelcache.bin";
  }

  fprintf(stderr, "lol\n");
  const char *supplies_ivers = iosvers;
  if (iosvers[0] != '9') {
   supplies_ivers = get_iosv(iosvers);
  }

  supplies_url = calloc(1, 
    strlen("http://wall.supplies/offsets/-")
    + strlen(idevice)
    + strlen(supplies_ivers));

  fprintf(stderr, "lol\n");
  sprintf(supplies_url, "http://wall.supplies/offsets/%s-%s", idevice, supplies_ivers);

  fprintf(stderr, "lol\n");
	if(process_kcache(path)) {
    free(supplies_url);
    return 1;
  }


  fprintf(stderr, "INFO: Offsets were written to '%s'. Good Luck!\n", OFFSETSJ_PATH);
  if (!is_decrypted) {
    fprintf(stderr, "INFO: You can compare first offsets to ones at\\\n");
    fprintf(stderr, "      '%s' to avoid bootloops\n", supplies_url);

    fprintf(stderr, "INFO: You can also run `shoff wall` to fetch offsets from wall.supplies\\\n");
    fprintf(stderr, "      if they're wrong\n");
  }

  fprintf(stderr, "INFO: Thanks to tihmstar, angelXwind, ianbeer, xninja (no order)\n");
  fprintf(stderr, "INFO: Contains code by badeip and planetbeing, see sources for details\n");

  fprintf(stderr, "INFO: Please, send offsets and device info to offsets@stek29.rocks if they work!\n");

  free(supplies_url);
  return 0;
}

int process_kcache(const char *filename) {
  FILE *obj_file = fopen(filename, "rb");
  if (obj_file == NULL) {
  	fprintf(stderr, "FAIL: Cant open file '%s'!\n", filename);
  	return 1;
  }

  int is_swap = 0;
  struct mach_header *mh = get_header(obj_file, &is_swap);
  if (mh == NULL) {
  	fprintf(stderr, "FAIL: Cant read mach-o header! (is it 32-bit?)\n");
  	return 1;
  };

  long load_cmds_offset = sizeof(struct mach_header);
  
  struct symtab_command *st = find_symtab(obj_file, load_cmds_offset, is_swap, mh->ncmds);
  if (st == NULL) {
  	fprintf(stderr, "FAIL: Cant find symtab!\n");
  	return 1;
  };
  fprintf(stderr, "INFO: Found symtab with %d syms\n", st->nsyms);

  struct segment_command *ts = NULL;
  int text_seg_offset = find_text_segment(obj_file, load_cmds_offset, is_swap, mh->ncmds, &ts);
  if (text_seg_offset < 0) {
  	fprintf(stderr, "FAIL: Cant find __TEXT!");
  	return 1;
  }
  LOAD_ADDR = ts->vmaddr;
  fprintf(stderr, "INFO: Found LOAD_ADDR: 0x%x\n", LOAD_ADDR);

  struct section tsect; 
  if (find_text_section(obj_file, ts, &tsect, text_seg_offset + sizeof(struct segment_command))) {
    fprintf(stderr, "FAIL: Cant find __text!\n");
    return 1;
  }

  fprintf(stderr, "INFO: Found __text, at 0x%x, size is 0x%x\n", tsect.offset, tsect.size);
  free(ts);

  char *vers = version(obj_file, st);
  if (vers != NULL) {
  	fprintf(stderr, "INFO: Kernel Version: '%s'\n", vers);
  } else {
  	fprintf(stderr, "FAIL: Cant read kernel version!\n");
  	return 1;
  }

  long ofs[18];
  memset(ofs, 0, sizeof(ofs));

  if (!use_supplies) {
    fprintf(stderr, "INFO: OSSerializer_serialize: 0x%lx\n", (ofs[0]=find_OSSerializer_serialize(obj_file, st)));
    fprintf(stderr, "INFO: OSSymbol_getMetaClass:  0x%lx\n", (ofs[1]=find_OSSymbol_getMetaClass(obj_file, st)));
    fprintf(stderr, "INFO: calend_gettime:         0x%lx\n", (ofs[2]=find_calend_gettime(obj_file)));
    fprintf(stderr, "INFO: bufattr_cpx:            0x%lx\n", (ofs[3]=find_bufattr_cpx(obj_file, st)));
    fprintf(stderr, "INFO: clock_ops:              0x%lx\n", (ofs[4]=find_clock_ops(obj_file, st)));
    fprintf(stderr, "INFO: copyin:                 0x%lx\n", (ofs[5]=find_copyin(obj_file, st)));
    fprintf(stderr, "INFO: bx_lr:                  0x%lx\n", (ofs[6]=find_bx_lr(obj_file, st)));
    fprintf(stderr, "INFO: write_gadget:           0x%lx\n", (ofs[7]=find_write_gadget(obj_file)));
    fprintf(stderr, "INFO: vm_kernel_addrperm:     0x%lx\n", (ofs[8]=find_vm_kernel_addrperm(obj_file, st)));
    fprintf(stderr, "INFO: kernel_pmap:            0x%lx\n", (ofs[9]=find_kernel_pmap(obj_file, st)));
    fprintf(stderr, "INFO: invalidate_tlb:         0x%lx\n", (ofs[10]=find_invalidate_tlb(obj_file)));
    fprintf(stderr, "INFO: allproc:                0x%lx\n", (ofs[11]=allproc(obj_file, st, &tsect)));
    fprintf(stderr, "INFO: proc_ucred:             0x%lx\n", (ofs[12]=proc_ucred(obj_file, st)));
  } else {
    fprintf(stderr, "INFO: Crawling '%s'...\n", supplies_url);
    char *command = calloc(1, strlen(supplies_url) + strlen("curl ''"));
    sprintf(command, "curl '%s'", supplies_url);
    FILE *curlfp = popen(command, "r");
    if (curlfp == NULL) {
      fprintf(stderr, "FAIL: Cant run %s\n", command);
      return 1;
    }

    char buf[128] = { 0 };
    int i = 0;
    while ((fgets(buf, sizeof(buf)-1, curlfp) != NULL) && i <= 12) {
      if (sscanf(buf, " 0x%lx", &ofs[i]) != 1) {
        fprintf(stderr, "FAIL: Cant parse '%s'\n", buf);
        return 1;
      }
      i++;
    }

    free(command);
    pclose(curlfp);
  }

  struct clock_ops_offset *unt = untether_clock_ops(obj_file, st, ofs[4]);

  if (unt != NULL) {
    fprintf(stderr, "INFO: c_config:               0x%lx\n", (ofs[13]=unt->c_config));
    fprintf(stderr, "INFO: c_init:                 0x%lx\n", (ofs[14]=unt->c_init));
    fprintf(stderr, "INFO: c_gettime:              0x%lx\n", (ofs[15]=unt->c_gettime));
    fprintf(stderr, "INFO: c_settime:              0x%lx\n", (ofs[16]=unt->c_settime));
    fprintf(stderr, "INFO: c_getattr:              0x%lx\n", (ofs[17]=unt->c_getattr));
  }

  fprintf(stderr, "INFO: Creating offsets.json...\n");

  FILE *offsetsj = fopen(OFFSETSJ_PATH, "w");
  if (offsetsj == NULL) {
  	fprintf(stderr, "FAIL: Cant open '%s' for writing!\n", OFFSETSJ_PATH);
  	return 1;
  }

  fprintf(offsetsj, "{\n");
  fprintf(offsetsj, "  \"%s\":\n", vers);
  fprintf(offsetsj, "   [\"0x%lx\",\n", ofs[0]);
  for (int i = 1; i < sizeof(ofs)/sizeof(ofs[0])-1; i++)
  	fprintf(offsetsj, "    \"0x%lx\",\n", ofs[i]);
  fprintf(offsetsj, "    \"0x%lx\"\n", ofs[sizeof(ofs)/sizeof(ofs[0])-1]);
  fprintf(offsetsj, "  ]\n");
  fprintf(offsetsj, "}");

  // cleanup
  fclose(offsetsj);

  free(vers);
  free(unt);
  fclose(obj_file);

  return 0;
}
