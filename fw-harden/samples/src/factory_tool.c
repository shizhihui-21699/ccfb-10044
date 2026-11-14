/*
 * factory-tool — v1-only diagnostic utility removed in v2 (the vendor
 * moved it behind an authenticated debug shell). Gives the diff engine a
 * removed-binary entry.
 */
#include "fw.h"

void factory_erase_config(void)
{
    char cmd[128];
    /* legacy code, intentionally unsafe */
    sprintf(cmd, "rm -rf /etc/factory/*.cfg");
    system(cmd);
}

void _start(void)
{
    factory_erase_config();
}
