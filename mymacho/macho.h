#include <mach-o/loader.h>


struct symtab_command *find_symtab(FILE *obj_file, int offset, int is_swap, uint32_t ncmds);
int find_text_segment(FILE *obj_file, int offset, int is_swap, uint32_t ncmds, struct segment_command **seg);
int find_text_section(FILE *obj_file, struct segment_command *ts, struct section *sect, long offset);
void *find_cmds(FILE *obj_file, int *offset, int is_swap, uint32_t *ncmds, uint32_t d_cmd);
struct mach_header* get_header(FILE *obj_file, int *is_swap);
int find_symbol_value(FILE *obj_file, struct symtab_command* st, const char symbol[], long *save_to);

