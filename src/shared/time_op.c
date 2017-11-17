/*
 * Time operations
 * Copyright (C) 2017 Wazuh Inc.
 * October 4, 2017
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#include "shared.h"

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

void w_gettime(struct timespec *ts) {
#ifdef __MACH__
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

double w_gettimed() {
    struct timespec ts;
    w_gettime(&ts);
    return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}

#endif // WIN32
