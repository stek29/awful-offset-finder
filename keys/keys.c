#include <string.h>

#include "keys.h"
#include "keys_gen.h"
#include "builds.h"

struct devinfo *get_dev_build(const char* idevice, const char* build) {
	struct devinfo *look_in = NULL;
	#define try_idv(idv)\
		if (strstr(idevice, "i"#idv) != NULL) {\
			idevice = idevice + strlen("i"#idv);\
			look_in = info_##idv;\
		}

	try_idv(Pad);
	try_idv(Pod);
	try_idv(Phone);

	#undef try_idv

	if (look_in == NULL)
		return NULL;

	while (look_in->idevice != NULL) {
		if (strcmp(idevice, look_in->idevice) == 0)
			if (strcmp(build, look_in->build) == 0)
				return look_in;
		look_in++;
	}

	return NULL;
};

struct devinfo *get_dev_iosv (const char* idevice, const char* iosv) {
	struct ios_build *build = ios_builds;

	while (build->vers != NULL) {
		if (strcmp(iosv, build->vers) == 0) {
			return get_dev_build(idevice, build->build);
		}

		build++;
	}

	return NULL;
}

const char *get_iosv(const char *build) {
	struct ios_build *ibuild = ios_builds;

	while (ibuild->vers != NULL) {
		if (strcmp(build, ibuild->build) == 0) {
			return ibuild->vers;
		}

		ibuild++;
	}

	return NULL;
}
