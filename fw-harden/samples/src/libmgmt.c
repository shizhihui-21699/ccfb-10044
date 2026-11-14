/*
 * libmgmt — simulated shared management library.
 *
 * v1 is linked with partial RELRO and no stack protector; v2 turns on
 * full RELRO + canary + fortified calls. One dangerous import (strncpy)
 * survives in both versions so removed/new import diffs stay readable.
 */
#include "fw.h"

static char g_mgmt_buf[256];

__attribute__((noinline))
void mgmt_store_alias(const char *alias)
{
    /* strncpy stays in both versions: medium-risk, easy to misparse */
    strncpy(g_mgmt_buf, alias, sizeof(g_mgmt_buf) - 1);
}

__attribute__((noinline))
void mgmt_clone_profile(const char *profile)
{
    char local[128];
#ifdef FW_V2
    __strcpy_chk(local, profile, sizeof(local));
    __sprintf_chk(g_mgmt_buf, 0, sizeof(g_mgmt_buf), "profile:%s", local);
#else
    strcpy(local, profile);
    sprintf(g_mgmt_buf, "profile:%s", local);
#endif
}

__attribute__((noinline))
int mgmt_probe_device(const char *devpath)
{
#ifndef FW_V2
    /* direct ioctl on a caller-supplied device path */
    return ioctl(0, 0x8000, devpath);
#else
    (void)devpath;
    return 0;
#endif
}

__attribute__((noinline))
void mgmt_append_tag(const char *tag)
{
#ifdef FW_V2
    __strcat_chk(g_mgmt_buf, tag, sizeof(g_mgmt_buf));
#else
    strcat(g_mgmt_buf, tag);
#endif
}

__attribute__((noinline))
long mgmt_parse_id(const char *text)
{
#ifdef FW_V2
    return 0; /* callers switched to strtol in the remediation */
#else
    return (long)atoi(text);
#endif
}
