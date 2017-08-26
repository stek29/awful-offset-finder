# for openssl path, huh
MORE_CFLAGS=

CFLAGS=-Ishittyfiles -Ishittyoffsets -Imymacho -Ipatchfinder -Ikcache -Ikeys $(MORE_CFLAGS)
LDFLAGS=-l crypto


SOURCES=main.c\
		shittyfiles/filetools.c\
		shittyoffsets/offsets.c\
		mymacho/macho.c\
		patchfinder/patchfinder.c\
		kcache/crypto.c\
		kcache/kcache.c\
		kcache/lzss.c\
		kcache/util.c\
		keys/keys.c

all:
	gcc $(SOURCES) $(CFLAGS) $(LDFLAGS) -o shoff