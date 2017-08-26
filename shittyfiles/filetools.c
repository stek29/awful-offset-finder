#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "filetools.h"

/*
// hex char to int
int hctoi(char hc) {
  if (hc >= '0' && hc <= '9') return hc - '0';
  if (hc >= 'a' && hc <= 'f') return hc - 'a' + 10;
  if (hc >= 'A' && hc <= 'F') return hc - 'A' + 10;
  return -1;
}


int main(int argc, char* argv[]) {
  if (argc != 4) return 2; // $0 filename start_offset hexstr

  FILE *f = fopen(argv[1], "rb");
  if (f == NULL) return 3;
  setbuf(f, NULL);

  int start_offset = atoi(argv[2]);
  
  char *hstr = argv[3];
  size_t hstrlen = strlen(hstr);

  if (hstrlen % 2 != 0) return 5;
  
  size_t datalen = hstrlen / 2;
  char *data = (char*)malloc(datalen * sizeof(char));

  if (data == NULL) return 6;

  for (int i = 0; i < datalen; i++) {
    data[i] = (hctoi(hstr[i*2])<<4) + hctoi(hstr[i*2+1]);
  }

  int offset = get_data_offset(data, datalen, f, start_offset, -1);

  if (offset != -1) {
    printf("0x%x\n", offset);
    return 0;
  } else {
    return 1;
  }
}
*/

void *load_bytes(FILE *f, int offset, int size) {
  void *buf = calloc(1, size);
  load_bytes_to_buf(f, offset, size, buf);
  return buf;
}

void load_bytes_to_buf(FILE *f, int offset, int size, void *buf) {
  if (offset != -1) {
    fseek(f, offset, SEEK_SET);
  }
  fread(buf, size, 1, f);
}

long get_data_offset(const void *data, int datalen, FILE *f, long offset, long maxlen) {
  long start_offset = offset;
  long read_until = (maxlen == -1) ? LONG_MAX : offset + maxlen;

  int found = 0;
  char* datac = (char*) data;
  int dati = 0;

  if (fseek(f, start_offset, SEEK_SET)) return -1;

  char ch;
  while (fread(&ch, sizeof(char), 1, f) == 1) {
    offset++;
    if (ch == datac[dati]) {
      dati++;
    } else {
      dati = 0;
    }

    if (dati == datalen) {
      found = 1;
      offset -= datalen;
      break;
    }

    if (offset > read_until) {
      break;
    }
  }

  return found ? offset - start_offset : -1;
}