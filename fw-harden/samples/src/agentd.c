/*
 * agentd — simulated field-bus agent, built as a fully static, stripped
 * executable. It exercises the analyzer's no-dynamic-section path:
 * no DT_NEEDED, symbols resolved inside the link, then llvm-strip removes
 * the symbol table so canary/FORTIFY answers must degrade to "unknown"
 * rather than false "disabled".
 */
#include "fw.h"

static char g_log[256];

__attribute__((noinline))
static void log_message(const char *msg)
{
    char local[96];
#ifdef FW_V2
    __memcpy_chk(g_log, msg, 64, sizeof(g_log));
#else
    memcpy(local, msg, 64);
    memcpy(g_log, local, 64);
#endif
}

__attribute__((noinline))
static void format_event(int code)
{
#ifdef FW_V2
    snprintf(g_log, sizeof(g_log), "event=%d", code);
#else
    sprintf(g_log, "event=%d raw=%s", code, g_log);
#endif
}

void agent_main(const char *msg, int code)
{
    log_message(msg);
    format_event(code);
}

void _start(void)
{
    agent_main("boot", 1);
}
