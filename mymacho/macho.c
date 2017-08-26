#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach-o/nlist.h>

#include "offsets.h"
#include "filetools.h"
#include "macho.h"

struct symtab_command *find_symtab(FILE *obj_file, int offset, int is_swap, uint32_t ncmds) {
  struct symtab_command *symtab = find_cmds(obj_file, &offset, is_swap, &ncmds, LC_SYMTAB);

  if (is_swap) {
    swap_symtab_command(symtab, 0);
  }

  return symtab;
}

int find_text_segment(FILE *obj_file, int offset, int is_swap, uint32_t ncmds, struct segment_command **seg) {
  const char segname[] = "__TEXT";
  *seg = NULL;

  while((*seg = find_cmds(obj_file, &offset, is_swap, &ncmds, LC_SEGMENT)) != NULL) {
    if (strcmp((*seg)->segname, segname) == 0) {
      return offset - (*seg)->cmdsize;
    } else {
      free(*seg);
    }
  }

  return -1;
}

int find_text_section(FILE *obj_file, struct segment_command *ts, struct section *sect, long offset) {
  const char sectname[] = "__text";

  for (uint32_t i = 0; i < ts->nsects; i++) {
    load_bytes_to_buf(obj_file, offset, sizeof(struct section), sect);
    printf("%s\n", sect->sectname);
    if (strcmp(sect->sectname, sectname) == 0) {
      return 0;
    } else {
      offset += sizeof(struct section);
    }
  }

  return 1;
}

void *find_cmds(FILE *obj_file, int *offset, int is_swap, 
    uint32_t *ncmds, uint32_t d_cmd) {

  int actual_offset = *offset;
  struct load_command *ret = NULL;

  for (int  i = 0; i < *ncmds && ret == NULL; i++) {
    struct load_command *cmd = load_bytes(obj_file, actual_offset, sizeof(struct load_command));
    if (is_swap) {
      swap_load_command(cmd, 0);
    }

    if (cmd->cmd == d_cmd) {
      ret = load_bytes(obj_file, actual_offset, cmd->cmdsize);
      *offset = actual_offset + cmd->cmdsize;
      *ncmds -= i;
    }

    actual_offset += cmd->cmdsize;
    free(cmd);
  }

  return ret;
}

struct mach_header* get_header(FILE *obj_file, int *is_swap) {
  uint32_t magic;
  fread(&magic, sizeof(uint32_t), 1, obj_file);

  *is_swap = magic == MH_CIGAM;

  if (magic != MH_CIGAM && magic != MH_MAGIC) { // 32 bit only
    return NULL;
  }

  int offset = 0;
  fseek(obj_file, offset, SEEK_SET);

  int header_size = sizeof(struct mach_header);
  struct mach_header *header = load_bytes(obj_file, offset, header_size);
  if (*is_swap) {
    swap_mach_header(header, 0);
  }

  return header;
}

int find_symbol_value(FILE *obj_file, struct symtab_command* st, const char symbol[], long *save_to) {
  size_t symbol_len = strlen(symbol);
  char *ssymbol = calloc(symbol_len + 2, sizeof(char));
  memcpy(ssymbol+1, symbol, symbol_len);

  long stroff = get_data_offset(ssymbol, symbol_len + 2, obj_file, st->stroff, st->strsize);
  free(ssymbol);

  if (stroff == -1) return -1;
  stroff++; // we've found '\0' before symbol

  fseek(obj_file, st->symoff, SEEK_SET);
  struct nlist nl;
  for (int i = 0; i < st->nsyms; i++) {
    load_bytes_to_buf(obj_file, -1, sizeof(struct nlist), &nl);

    if (nl.n_un.n_strx == stroff) {
      *save_to = nl.n_value;
      return 0;
    }
  }

  return -3;
}
