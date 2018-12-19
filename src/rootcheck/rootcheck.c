/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Rootcheck
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 * http://www.ossec.net/rootcheck/
 */

#include "headers/shared.h"
#include "rootcheck.h"

rkconfig rootcheck;
char **rk_sys_file;
char **rk_sys_name;
int rk_sys_count;
char total_ports_udp[65535 + 1];
char total_ports_tcp[65535 + 1];

#ifndef ARGV0
#define ARGV0 "rootcheck"
#endif

#ifndef OSSECHIDS

int main(int argc, char **argv)
{
    int test_config = 0;
    const char *cfg = "./rootcheck.conf";
	
#else

int rootcheck_init(int test_config)
{
    const char *cfg = DEFAULTCPATH;

#endif

    int c;

    /* Zero the structure, initialize default values */
    rootcheck.workdir = NULL;
    rootcheck.basedir = NULL;
    rootcheck.unixaudit = NULL;
    rootcheck.ignore = NULL;
    rootcheck.rootkit_files = NULL;
    rootcheck.rootkit_trojans = NULL;
    rootcheck.winaudit = NULL;
    rootcheck.winmalware = NULL;
    rootcheck.winapps = NULL;
    rootcheck.daemon = 1;
    rootcheck.scanall = 0;
    rootcheck.readall = 0;
    rootcheck.disabled = RK_CONF_UNPARSED;
    rootcheck.skip_nfs = 0;
    rootcheck.alert_msg = NULL;
    rootcheck.time = ROOTCHECK_WAIT;

    rootcheck.checks.rc_dev = 1;
    rootcheck.checks.rc_files = 0;
    rootcheck.checks.rc_if = 1;
    rootcheck.checks.rc_pids = 1;
    rootcheck.checks.rc_ports = 1;
    rootcheck.checks.rc_sys = 1;
    rootcheck.checks.rc_trojans = 0;
#ifdef WIN32
    rootcheck.checks.rc_winaudit = 0;
    rootcheck.checks.rc_winmalware = 0;
    rootcheck.checks.rc_winapps = 0;
#else
    rootcheck.checks.rc_unixaudit = 0;
#endif

    /* We store up to 255 alerts in there */
    os_calloc(256, sizeof(char *), rootcheck.alert_msg);
    c = 0;
    while (c <= 255) {
        rootcheck.alert_msg[c] = NULL;
        c++;
    }


#ifdef WIN32
    /* Start Winsock */
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
            mterror_exit(ARGV0, "WSAStartup() failed");
        }
    }
#endif /* WIN32 */

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        mterror(ARGV0, "Configuration file '%s' not found", cfg);
        return (-1);
    }

    /* Read configuration  --function specified twice (check makefile) */
    if (Read_Rootcheck_Config(cfg) < 0) {
        mterror_exit(ARGV0, CONFIG_ERROR, cfg);
    }

    rootcheck.tsleep = getDefine_Int("rootcheck", "sleep", 0, 1000);

    /* If testing config, exit here */
    if (test_config) {
        return (0);
    }

    /* Return 1 disables rootcheck */
    if (rootcheck.disabled == 1) {
        mtinfo(ARGV0, "Rootcheck disabled.");
        return (1);
    }

    mtdebug1(ARGV0, STARTED_MSG);

#ifndef WIN32
    /* Check if Unix audit file is configured */
    if (rootcheck.checks.rc_unixaudit && !rootcheck.unixaudit) {
        mtferror(ARGV0, "System audit file not configured.");
    }
#endif

    /* Set default values */
    if (rootcheck.workdir == NULL) {
        rootcheck.workdir = DEFAULTDIR;
    }

    /* Start up message */
#ifdef WIN32
    mtinfo(ARGV0, STARTUP_MSG, getpid());
#endif /* WIN32 */

    /* Initialize rk list */
    rk_sys_name = (char **) calloc(MAX_RK_SYS + 2, sizeof(char *));
    rk_sys_file = (char **) calloc(MAX_RK_SYS + 2, sizeof(char *));
    if (!rk_sys_name || !rk_sys_file) {
        mterror_exit(ARGV0, MEM_ERROR, errno, strerror(errno));
    }
    rk_sys_name[0] = NULL;
    rk_sys_file[0] = NULL;

#ifndef WIN32
    rootcheck_connect();
#endif
    mtdebug1(ARGV0, "Running run_rk_check");
    run_rk_check();

    mtdebug1(ARGV0, "Leaving...");
    return (0);
}

void rootcheck_connect() {
#ifndef WIN32
    /* Connect to the queue */
    mtdebug1(ARGV0, "Starting queue ...");

    /* Start the queue */
    if ((rootcheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
        mterror_exit(ARGV0, QUEUE_FATAL, DEFAULTQPATH);
    }
#endif
}
