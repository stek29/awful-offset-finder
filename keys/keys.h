struct devinfo {
  char *idevice;
  char *build;
  char *iv;
  char *key;
};

struct devinfo *get_dev_build(const char* idevice, const char* build);
struct devinfo *get_dev_iosv (const char* idevice, const char* iosv);
const char *get_iosv(const char *build);
