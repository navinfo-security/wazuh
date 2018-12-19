/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck.h"

static void free_pm(pm_stats * pm_data);


/* Read the file pointer specified
 * and check if the configured file is there
 */
int check_rc_unixaudit(FILE *fp, OSList *p_list)
{
    mtdebug1(ARGV0, "Starting on check_rc_unixaudit");
    pm_stats * pm_data = NULL;
    os_strdup("system audit", pm_data->type);
    if (pm_get_entry(fp, pm_data, p_list) < 0) {
        free_pm(pm_data);
        return -1;
    }
    return 0;
}

/* Read the file pointer specified
 * and check if the configured file is there
 */
int check_rc_winaudit(FILE *fp, OSList *p_list)
{
    mtdebug1(ARGV0, "Starting on check_rc_winaudit");
    pm_stats * pm_data = NULL;
    os_strdup("Windows audit", pm_data->type);
    if (pm_get_entry(fp, pm_data, p_list) < 0) {
        free_pm(pm_data);
        return -1;
    }
    return 0;
}

/* Read the file pointer specified
 * and check if the configured file is there
 */
int check_rc_winmalware(FILE *fp, OSList *p_list)
{
    mtdebug1(ARGV0, "Starting on check_rc_winmalware");
    pm_stats * pm_data = NULL;
    os_strdup("Windows malware", pm_data->type);
    if (pm_get_entry(fp, pm_data, p_list) < 0) {
        free_pm(pm_data);
        return -1;
    }
    return 0;
}

/* Read the file pointer specified
 * and check if the configured file is there
 */
int check_rc_winapps(FILE *fp, OSList *p_list)
{
    mtdebug1(ARGV0, "Starting on check_rc_winapps");
    pm_stats * pm_data = NULL;
    os_strdup("Windows application", pm_data->type);
    if (pm_get_entry(fp, pm_data, p_list) < 0) {
        free_pm(pm_data);
        return -1;
    }
    return 0;
}

static void free_pm(pm_stats * pm_data) {
    if (pm_data->type)
        free(pm_data->type);

    if (pm_data->profile)
        free(pm_data->profile);

    free(pm_data);
}
