/*
 * gatewayd — simulated IoT gateway management daemon.
 *
 * The same source is built twice:
 *   v1: legacy build, weak hardening, numerous dangerous libc calls
 *   v2 (-DFW_V2): security-remediated build, with two deliberate
 *       regressions (new popen() usage and relaxed RELRO/NX on some
 *       profiles) so the diff engine has something to report.
 *
 * Code never actually runs; it exists to produce realistic import tables
 * and hardening metadata under different toolchain flags.
 */
#include "fw.h"

#define COMMAND_BUF 256
#define PATH_BUF 128

static char g_config[512];
static char g_scratch[256];

__attribute__((noinline))
static void parse_device_name(const char *input)
{
    char local[64];
#ifdef FW_V2
    /* bounded copy + fortified memory move */
    strncpy(local, input, sizeof(local) - 1);
    local[sizeof(local) - 1] = 0;
    __memcpy_chk(g_scratch, local, sizeof(local), sizeof(g_scratch));
#else
    /* classic unbounded stack overflow pattern */
    strcpy(local, input);
    strcat(local, "-device");
    memcpy(g_scratch, local, sizeof(local));
#endif
}

__attribute__((noinline))
static void build_status_line(int unit_id, const char *state)
{
#ifdef FW_V2
    snprintf(g_config, sizeof(g_config), "unit=%d state=%s", unit_id, state);
#else
    /* unbounded formatted write */
    sprintf(g_config, "unit=%d state=%s note=%s", unit_id, state, g_scratch);
#endif
}

__attribute__((noinline))
static int load_config(const char *path)
{
    char line[128];
    int id = 0;
#ifdef FW_V2
    char *tok_ctx = 0;
    char *tok = strtok_r(g_config, "=", &tok_ctx);
    (void)path;
    (void)line;
#else
    /* non-reentrant parser */
    char *tok = strtok(g_config, "=");
    /* environment-controlled configuration path */
    const char *env = getenv("GW_CONFIG_HOME");
    (void)env;
    (void)path;
    (void)line;
#endif
    while (tok) {
        id += atoi(tok);
#ifdef FW_V2
        tok = strtok_r(0, "=", &tok_ctx);
#else
        tok = strtok(0, "=");
#endif
    }
    return id;
}

__attribute__((noinline))
static void run_maintenance(const char *iface)
{
    char cmd[COMMAND_BUF];
#ifdef FW_V2
    /*
     * Deliberate regression: remediation replaced system() but introduced
     * popen(), which has the same shell-injection exposure.
     */
    snprintf(cmd, sizeof(cmd), "ping -c1 %s", iface);
    popen(cmd, "r");
#else
    sprintf(cmd, "ifup %s && ping -c1 %s", iface, iface);
    system(cmd);
#endif
}

__attribute__((noinline))
static void fetch_plugin(const char *plugin_name)
{
#ifdef FW_V2
    /* dlopen/dlsym removed; plugin table is now statically linked */
    (void)plugin_name;
#else
    char path[PATH_BUF];
    sprintf(path, "/opt/firmware/plugins/%s.so", plugin_name);
    void *h = dlopen(path, 2 /* RTLD_NOW */);
    if (h) {
        void (*init)(void) = (void (*)(void))dlsym(h, "plugin_init");
        if (init)
            init();
    }
#endif
}

__attribute__((noinline))
static void read_serial_packet(int fd)
{
    unsigned char packet[128];
#ifdef FW_V2
    __memcpy_chk(g_scratch, (char *)packet, 64, sizeof(g_scratch));
#else
    read(fd, packet, sizeof(packet));
    memcpy(g_scratch, packet, 64);
#endif
}

__attribute__((noinline))
static void legacy_console(char *buf)
{
#ifndef FW_V2
    /* gets() was removed in C11; kept only in the legacy build */
    gets(buf);
#endif
}

__attribute__((noinline))
static void temp_file_handling(void)
{
#ifndef FW_V2
    char name[PATH_BUF];
    tmpnam(name);
    rand();
#else
    /* predictable-name APIs and non-crypto PRNG removed */
#endif
}

void gateway_main(const char *device, const char *iface, const char *plugin, int fd)
{
    char frame[160];
    parse_device_name(device);
    build_status_line(1, "up");
    load_config((const char *)0);
    run_maintenance(iface);
    fetch_plugin(plugin);
    read_serial_packet(fd);
    legacy_console(frame);
    temp_file_handling();
}

/* freestanding entry point */
void _start(void)
{
    gateway_main("sensor-a", "eth0", "modbus", 3);
}
