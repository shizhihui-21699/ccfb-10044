/*
 * libwatchdog — small v2-only shared library, linked into gatewayd in the
 * new firmware. Exists to give the diff engine a genuine new DT_NEEDED
 * dependency and a new binary to report.
 */
#include "fw.h"

static char g_wd_state[64];

__attribute__((noinline))
void watchdog_kick(const char *reason)
{
    /* bounded copy: this library follows the v2 hardening standard */
    strncpy(g_wd_state, reason, sizeof(g_wd_state) - 1);
    g_wd_state[sizeof(g_wd_state) - 1] = 0;
}
