/*
 * Freestanding prototypes for the simulated firmware.
 * No libc headers are used so the samples cross-link with lld on every
 * supported target without a sysroot.
 */
#ifndef FW_SAMPLES_FW_H
#define FW_SAMPLES_FW_H

typedef unsigned long size_t;
typedef long ssize_t;

/* string / memory */
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strcat(char *dst, const char *src);
char *strncat(char *dst, const char *src, size_t n);
size_t strlen(const char *s);
char *strtok(char *s, const char *sep);
char *strtok_r(char *s, const char *sep, char **last);
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int sprintf(char *s, const char *fmt, ...);
int snprintf(char *s, size_t n, const char *fmt, ...);
int sscanf(const char *s, const char *fmt, ...);
char *gets(char *s);
char *fgets(char *s, int n, void *f);

/* fortified variants (resolved at link time to undefined symbols) */
void *__memcpy_chk(void *dst, const void *src, size_t n, size_t dstlen);
char *__strcpy_chk(char *dst, const char *src, size_t dstlen);
int __sprintf_chk(char *s, int flag, size_t dstlen, const char *fmt, ...);
char *__strcat_chk(char *dst, const char *src, size_t dstlen);

/* process / loader */
int system(const char *cmd);
void *popen(const char *cmd, const char *mode);
int execl(const char *path, const char *arg0, ...);
int execlp(const char *file, const char *arg0, ...);
int execvp(const char *file, char *const argv[]);
void *dlopen(const char *path, int mode);
void *dlsym(void *handle, const char *symbol);
void abort(void);

/* env / temp / random */
char *getenv(const char *name);
char *tmpnam(char *s);
int rand(void);
long random(void);
int atoi(const char *s);

/* files / devices */
int chmod(const char *path, unsigned mode);
int chown(const char *path, unsigned uid, unsigned gid);
int ioctl(int fd, unsigned long req, ...);
ssize_t read(int fd, void *buf, size_t n);

/* stack protector, supplied by the simulated support runtime */
void __stack_chk_fail(void);

#endif
