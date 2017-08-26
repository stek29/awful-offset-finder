#include <stdio.h>

long get_data_offset(const void *data, int datalen, FILE *f, long offset, long maxlen);
void *load_bytes(FILE *f, int offset, int size);
void load_bytes_to_buf(FILE *f, int offset, int size, void *buf);
