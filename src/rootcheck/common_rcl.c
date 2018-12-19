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

/* Prototypes */
static char *_rkcl_getfp(FILE *fp, char *buf);
static int _rkcl_is_header(const char *buf);
static int _rkcl_get_vars(OSStore *vars, char *nbuf);
static cJSON * read_check_metadata(char * buf, int * condition);
static char *_rkcl_get_pattern(char *value);
static char *_rkcl_get_value(char *buf, int *type);

/* Types of values */
#define RKCL_TYPE_FILE      1
#define RKCL_TYPE_REGISTRY  2
#define RKCL_TYPE_PROCESS   3
#define RKCL_TYPE_DIR       4

#define RKCL_COND_ALL       0x001
#define RKCL_COND_ANY       0x002
#define RKCL_COND_REQ       0x004
#define RKCL_COND_NON       0x008
#define RKCL_COND_INV       0x016

#ifdef WIN32
char *_rkcl_getrootdir(char *root_dir, int dir_size)
{
    char final_file[2048 + 1];
    char *tmp;

    final_file[0] = '\0';
    final_file[2048] = '\0';

    ExpandEnvironmentStrings("%WINDIR%", final_file, 2047);

    tmp = strchr(final_file, '\\');
    if (tmp) {
        *tmp = '\0';
        strncpy(root_dir, final_file, dir_size);
        return (root_dir);
    }

    return (NULL);
}
#endif

/* Get next available buffer in file */
static char *_rkcl_getfp(FILE *fp, char *buf)
{
    while (fgets(buf, OS_SIZE_2048, fp) != NULL) {
        char *nbuf;

        /* Remove end of line */
        nbuf = strchr(buf, '\n');
        if (nbuf) {
            *nbuf = '\0';
        }

        /* Assign buf to be used */
        nbuf = buf;

        /* Exclude commented lines or blanked ones */
        while (*nbuf != '\0') {
            if (*nbuf == ' ' || *nbuf == '\t') {
                nbuf++;
                continue;
            } else if (*nbuf == '#') {
                *nbuf = '\0';
                continue;
            } else {
                break;
            }
        }

        /* Go to next line if empty */
        if (*nbuf == '\0') {
            continue;
        }

        return (nbuf);
    }

    return (NULL);
}

static int _rkcl_is_header(const char *buf)
{
    if (*buf == '{' && buf[strlen(buf) - 1] == '}') {
        return (1);
    }
    return (0);
}

static int _rkcl_get_vars(OSStore *vars, char *nbuf)
{
    char *var_value;
    char *tmp;

    /* If not a variable, return 0 */
    if (*nbuf != '$') {
        return (0);
    }

    /* Remove semicolon from the end */
    tmp = strchr(nbuf, ';');
    if (tmp) {
        *tmp = '\0';
    } else {
        return (-1);
    }

    /* Get value */
    tmp = strchr(nbuf, '=');
    if (tmp) {
        *tmp = '\0';
        tmp++;
    } else {
        return (-1);
    }

    /* Dump the variable options */
    os_strdup(tmp, var_value);

    /* Add entry to the storage */
    OSStore_Put(vars, nbuf, var_value);
    return (1);
}

/* Read the JSON header of every check */
static cJSON * read_check_metadata(char * buf, int * condition) {

    cJSON * header = NULL;
    char tmp_cond[OS_SIZE_128];

    header = cJSON_Parse(buf);
    if (!header) {
        return NULL;
    }

    snprintf(tmp_cond, OS_SIZE_128 - 1, "%s", cJSON_GetObjectItem(header, "condition")->valuestring);
    /* Get condition */
    if (strcmp(tmp_cond, "all") == 0) {
        *condition |= RKCL_COND_ALL;
    } else if (strcmp(tmp_cond, "any") == 0) {
        *condition |= RKCL_COND_ANY;
    } else if (strcmp(tmp_cond, "none") == 0) {
        *condition |= RKCL_COND_NON;
    } else if (strcmp(tmp_cond, "any required") == 0) {
        *condition |= RKCL_COND_ANY;
        *condition |= RKCL_COND_REQ;
    } else if (strcmp(tmp_cond, "all required") == 0) {
        *condition |= RKCL_COND_ALL;
        *condition |= RKCL_COND_REQ;
    } else {
        *condition = RKCL_COND_INV;
    }

    cJSON_DeleteItemFromObject(header, "condition");
    return header;
}

static char *_rkcl_get_pattern(char *value)
{
    while (*value != '\0') {
        if ((*value == ' ') && (value[1] == '-') &&
                (value[2] == '>') && (value[3] == ' ')) {
            *value = '\0';
            value += 4;

            return (value);
        }
        value++;
    }

    return (NULL);
}

static char *_rkcl_get_value(char *buf, int *type)
{
    char *tmp_str;
    char *value;

    /* Zero type before using it to make sure return is valid
     * in case of error.
     */
    *type = 0;

    value = strchr(buf, ':');
    if (value == NULL) {
        return (NULL);
    }

    *value = '\0';
    value++;

    tmp_str = strchr(value, ';');
    if (tmp_str == NULL) {
        return (NULL);
    }
    *tmp_str = '\0';

    /* Get types - removing negate flag (using later) */
    if (*buf == '!') {
        buf++;
    }

    if (strcmp(buf, "f") == 0) {
        *type = RKCL_TYPE_FILE;
    } else if (strcmp(buf, "r") == 0) {
        *type = RKCL_TYPE_REGISTRY;
    } else if (strcmp(buf, "p") == 0) {
        *type = RKCL_TYPE_PROCESS;
    } else if (strcmp(buf, "d") == 0) {
        *type = RKCL_TYPE_DIR;
    } else {
        return (NULL);
    }

    return (value);
}

int pm_get_entry(FILE *fp, pm_stats * pm_data, OSList *p_list) {

    int type = 0, condition = 0;
    char * nbuf;
    char buf[OS_SIZE_2048 + 2];
    char root_dir[OS_SIZE_1024 + 2];
    char final_file[OS_SIZE_2048 + 1];
    char *value;
    OSStore *vars;

    cJSON * json_header = NULL;
    cJSON * files = NULL;
    cJSON * directories = NULL;
    cJSON * processes = NULL;
#ifdef WIN32
    cJSON * registries = NULL;
#endif

    /* Initialize variables */
    memset(buf, '\0', sizeof(buf));
    memset(root_dir, '\0', sizeof(root_dir));

    #ifdef WIN32
        /* Get Windows rootdir */
        _rkcl_getrootdir(root_dir, sizeof(root_dir) - 1);
        if (root_dir[0] == '\0') {
            mterror(ARGV0, INVALID_ROOTDIR);
        }
    #endif

    /* Get variables */
    vars = OSStore_Create();

    /* We first read all variables -- they must be defined at the top */
    while (1) {
        int rc_code = 0;
        nbuf = _rkcl_getfp(fp, buf);
        if (nbuf == NULL) {
            goto clean_error;
        }

        rc_code = _rkcl_get_vars(vars, nbuf);
        if (rc_code == 0) {
            break;
        } else if (rc_code == -1) {
            mterror(ARGV0, INVALID_RKCL_VAR, nbuf);
            goto clean_error;
        }
    }

    /* Get the profile of the file */
    nbuf = _rkcl_getfp(fp, buf);
    if (nbuf == NULL) {
        goto clean_error;
    } else if (!strncmp(nbuf, "Profile", 7)) {
        if (nbuf = strchr(nbuf, ':'), nbuf) {
            nbuf = w_strtrim(nbuf);
            os_strdup(nbuf, pm_data->profile);
        } else {
            os_strdup("unknown", pm_data->profile);
        }
    } else {
        mterror(ARGV0, INVALID_RKCL_PROF, nbuf);
        goto clean_error;
    }

    /* Read first metadata line */

    nbuf = _rkcl_getfp(fp, buf);
    if (nbuf == NULL) {
        goto clean_error;
    }

    while (nbuf != NULL) {

        json_header = read_check_metadata(nbuf, &condition);
        if (!json_header || condition == RKCL_COND_INV) {
            mterror(ARGV0, INVALID_RKCL_NAME, nbuf);
            goto clean_error;
        }

        mtdebug2(ARGV0, "Checking Policy Monitoring ID: %d", cJSON_GetObjectItem(json_header, "pm_id")->valueint);

        int g_found = 0;
        int not_found = 0;

        /* Inicialize arrays for monitored resources */
        files = cJSON_CreateArray();
        directories = cJSON_CreateArray();
        processes = cJSON_CreateArray();
#ifdef WIN32
        registries = cJSON_CreateArray();
#endif

        /* Get values from each entry */
        do {
            int negate = 0;
            int found = 0;
            value = NULL;

            nbuf = _rkcl_getfp(fp, buf);
            if (nbuf == NULL) {
                break;
            }

            if (_rkcl_is_header(nbuf)) {
                break;
            }

            value = _rkcl_get_value(nbuf, &type);
            if (value == NULL) {
                mterror(ARGV0, INVALID_RKCL_VALUE, nbuf);
                goto clean_error;
            }

            if (*value == '!') {
                negate = 1;
                value++;
            }

            /* Check for a file */
            if (type == RKCL_TYPE_FILE) {
                char *pattern = NULL;
                char *f_value = NULL;

                pattern = _rkcl_get_pattern(value);
                f_value = value;

                /* Get any variable */
                if (value[0] == '$') {
                    f_value = (char *) OSStore_Get(vars, value);
                    if (!f_value) {
                        mterror(ARGV0, INVALID_RKCL_VAR, value);
                        continue;
                    }
                }

#ifdef WIN32
                else if (value[0] == '\\') {
                    final_file[0] = '\0';
                    final_file[sizeof(final_file) - 1] = '\0';

                    snprintf(final_file, sizeof(final_file) - 2, "%s%s",
                             root_dir, value);
                    f_value = final_file;
                } else {
                    final_file[0] = '\0';
                    final_file[sizeof(final_file) - 1] = '\0';

                    ExpandEnvironmentStrings(value, final_file,
                                             sizeof(final_file) - 2);
                    f_value = final_file;
                }
#endif

                mtdebug2(ARGV0, "Checking file: '%s'.", f_value);
                if (rk_check_file(f_value, pattern)) {
                    mtdebug2(ARGV0, "Found file.");
                    found = 1;
                }
                cJSON_AddItemToArray(files, cJSON_CreateString(f_value));
            }

#ifdef WIN32
            /* Check for a registry entry */
            else if (type == RKCL_TYPE_REGISTRY) {
                char *entry = NULL;
                char *pattern = NULL;

                /* Look for additional entries in the registry
                 * and a pattern to match.
                 */
                entry = _rkcl_get_pattern(value);
                if (entry) {
                    pattern = _rkcl_get_pattern(entry);
                }

                mtdebug2(ARGV0, "Checking registry: '%s'.", value);
                if (is_registry(value, entry, pattern)) {
                    mtdebug2(ARGV0, "Found registry.");
                    found = 1;
                }
                cJSON_AddItemToArray(registries, cJSON_CreateString(value));
            }
#endif

            /* Check for a directory */
            else if (type == RKCL_TYPE_DIR) {
                char *file = NULL;
                char *pattern = NULL;
                char *f_value = NULL;
                char *dir = NULL;

                file = _rkcl_get_pattern(value);
                if (!file) {
                    mterror(ARGV0, INVALID_RKCL_VAR, value);
                    continue;
                }

                pattern = _rkcl_get_pattern(file);

                /* Get any variable */
                if (value[0] == '$') {
                    f_value = (char *) OSStore_Get(vars, value);
                    if (!f_value) {
                        mterror(ARGV0, INVALID_RKCL_VAR, value);
                        continue;
                    }
                } else {
                    f_value = value;
                }

                /* Check for multiple comma separated directories */
                dir = f_value;
                f_value = strchr(dir, ',');
                if (f_value) {
                    *f_value = '\0';
                }

                while (dir) {

                    mtdebug2(ARGV0, "Checking dir: %s", dir);

                    short is_nfs = IsNFS(dir);
                    if( is_nfs == 1 && rootcheck.skip_nfs ) {
                        mtdebug1(ARGV0, "rootcheck.skip_nfs enabled and %s is flagged as NFS.", dir);
                    }
                    else {
                        mtdebug2(ARGV0, "%s => is_nfs=%d, skip_nfs=%d", dir, is_nfs, rootcheck.skip_nfs);

                        if (rk_check_dir(dir, file, pattern)) {
                            mtdebug2(ARGV0, "Found dir.");
                            found = 1;
                        }
                        cJSON_AddItemToArray(directories, cJSON_CreateString(dir));
                    }

                    if (f_value) {
                        *f_value = ',';
                        f_value++;

                        dir = f_value;

                        f_value = strchr(dir, ',');
                        if (f_value) {
                            *f_value = '\0';
                        }
                    } else {
                        dir = NULL;
                    }
                }
            }

            /* Check for a process */
            else if (type == RKCL_TYPE_PROCESS) {
                if (is_process(value, p_list)) {
                    mtdebug2(ARGV0, "Found process: '%s", value);
                    found = 1;
                }
                cJSON_AddItemToArray(processes, cJSON_CreateString(value));
            }

            /* Switch the values if ! is present */
            if (negate) {
                if (found) {
                    found = 0;
                } else {
                    found = 1;
                }
            }

            /* Check the conditions */
            if (condition & RKCL_COND_ANY) {
                mtdebug2(ARGV0, "Condition ANY.");
                if (found) {
                    g_found = 1;
                }
            } else if (condition & RKCL_COND_NON) {
                mtdebug2(ARGV0, "Condition NON.");
                if (!found && (not_found != -1)) {
                    mtdebug2(ARGV0, "Condition NON setze not_found=1.");
                    not_found = 1;
                } else {
                    not_found = -1;
                }
            } else {
                /* Condition for ALL */
                mtdebug2(ARGV0, "Condition ALL.");
                if (found && (g_found != -1)) {
                    g_found = 1;
                } else {
                    g_found = -1;
                }
            }
        } while (value != NULL);

        if (condition & RKCL_COND_NON) {
           if (not_found == -1){ g_found = 0;} else {g_found = 1;}
        }

        if (g_found == 1) {
            cJSON_AddStringToObject(json_header, "result", "fail");
        } else {
            if (condition & RKCL_COND_REQ) {
                goto clean_error;
            }
            cJSON_AddStringToObject(json_header, "result", "pass");
        }

        /* Include involved sources */
        if (cJSON_GetArraySize(files) > 0) {
            cJSON_AddItemToObject(json_header, "files", files);
        } else {
            cJSON_Delete(files);
        }
        if (cJSON_GetArraySize(directories) > 0) {
            cJSON_AddItemToObject(json_header, "directories", directories);
        } else {
            cJSON_Delete(directories);
        }
        if (cJSON_GetArraySize(processes) > 0) {
            cJSON_AddItemToObject(json_header, "processes", processes);
        } else {
            cJSON_Delete(processes);
        }
#ifdef WIN32
        if (cJSON_GetArraySize(registries) > 0) {
            cJSON_AddItemToObject(json_header, "registries", registries);
        } else {
            cJSON_Delete(registries);
        }
#endif

        /* Send check result to the queue */
        char * msg;
        msg = cJSON_PrintUnformatted(json_header);
        notify_rk(ALERT_POLICY_VIOLATION, msg);
        cJSON_Delete(json_header);
        free(msg);

    }

    OSStore_Free(vars);
    return 0;

    /* Clean up memory */
clean_error:

    if (files) {
        cJSON_Delete(files);
    }
    if (directories) {
        cJSON_Delete(directories);
    }
    if (processes) {
        cJSON_Delete(processes);
    }
#ifdef WIN32
    if (registries) {
        cJSON_Delete(registries);
    }
#endif
    if (json_header) {
        cJSON_Delete(json_header);
    }
    OSStore_Free(vars);

    return (-1);
}