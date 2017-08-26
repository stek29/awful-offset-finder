#include <stdio.h>
#include <stdlib.h>
#include <mach-o/loader.h>

uint32_t LOAD_ADDR;

char *version(FILE *f, struct symtab_command *st);

long find_OSSerializer_serialize(FILE *f, struct symtab_command *st);
long find_OSSymbol_getMetaClass(FILE *f, struct symtab_command *st);
long find_calend_gettime(FILE *f);
long find_bufattr_cpx(FILE *f, struct symtab_command *st);
long find_clock_ops(FILE *f, struct symtab_command *st);
long find_copyin(FILE *f, struct symtab_command *st);
long find_bx_lr(FILE *f, struct symtab_command *st);
long find_write_gadget(FILE *f);
long find_vm_kernel_addrperm(FILE *f, struct symtab_command *st);
long find_kernel_pmap(FILE *f, struct symtab_command *st);
long find_invalidate_tlb(FILE *f);
long allproc(FILE *f, struct symtab_command *st, struct section *tsect);
long proc_ucred(FILE *f, struct symtab_command *st);

struct clock_ops_offset {
  uint32_t c_config;
  uint32_t c_init;
  uint32_t c_gettime;
  uint32_t c_settime;
  uint32_t c_getattr;
  /*
  uint32_t c_setattr;
  uint32_t c_setalrm;
  */
};

struct clock_ops_offset *untether_clock_ops(FILE *f, struct symtab_command *st, long clock_ops);

