/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Rootcheck decoder */

#include "config.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "rootcheck_op.h"
#include <pthread.h>
#include "os_net/os_net.h"

#define ROOTCHECK_DIR    "/queue/rootcheck"

/* Local variables */
static char *rk_agent_ips[MAX_AGENTS];
static FILE *rk_agent_fps[MAX_AGENTS];
static int rk_err;
static int fts_r;

/* Rootcheck decoder */
static OSDecoderInfo *rootcheck_dec = NULL;

/* Rootcheck mutex */
static pthread_mutex_t rootcheck_mutex[MAX_AGENTS];

/* Rootcheck Wazuh DB functions */
static int QueryRootcheck(Eventinfo *lf);
static int SaveRootcheck(Eventinfo *lf, int exists);
static int rk_send_db(char * msg, char * response);

/* Initialize the necessary information to process the rootcheck information */
void RootcheckInit()
{
    int i = 0;

    rk_err = 0;

    for (; i < MAX_AGENTS; i++) {
        rk_agent_ips[i] = NULL;
        rk_agent_fps[i] = NULL;
        rootcheck_mutex[i] = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    }

    /* Zero decoder */
    os_calloc(1, sizeof(OSDecoderInfo), rootcheck_dec);
    rootcheck_dec->id = getDecoderfromlist(ROOTCHECK_MOD);
    rootcheck_dec->type = OSSEC_RL;
    rootcheck_dec->name = ROOTCHECK_MOD;
    rootcheck_dec->fts = 0;
    fts_r = 0;

    /* New fields as dynamic */

    os_calloc(Config.decoder_order_size, sizeof(char *), rootcheck_dec->fields);
    rootcheck_dec->fields[RK_TITLE] = "title";
    rootcheck_dec->fields[RK_FILE] = "file";

    mdebug1("RootcheckInit completed.");

    return;
}

/* Return the file pointer to be used */
static FILE *RK_File(const char *agent, int *agent_id)
{
    int i;
    int found = 0;
    char rk_buf[OS_SIZE_1024 + 1];

    for (i = 0; i < MAX_AGENTS && rk_agent_ips[i]; i++) {
        if (strcmp(rk_agent_ips[i], agent) == 0) {
            snprintf(rk_buf, OS_SIZE_1024, "%s/%s", ROOTCHECK_DIR, agent);

            found = 1;
            w_mutex_lock(&rootcheck_mutex[i]);

            if (!IsFile(rk_buf)) {
                /* Pointing to the beginning of the file */
                fseek(rk_agent_fps[i], 0, SEEK_SET);
                *agent_id = i;
                return (rk_agent_fps[i]);
            } else {
                // File was deleted. Close and let reopen.
                mwarn("Rootcheck database '%s' has been deleted. Recreating.", agent);
                fclose(rk_agent_fps[i]);
                free(rk_agent_ips[i]);
                rk_agent_ips[i] = NULL;
                break;
            }
        }
    }

    /* If here, our agent wasn't found */
    if(!found){
        if (i == MAX_AGENTS) {
            merror("Rootcheck decoder: exceeding agent limit (%d)", MAX_AGENTS);
            return NULL;
        }

        w_mutex_lock(&rootcheck_mutex[i]);
    }

    rk_agent_ips[i] = strdup(agent);

    if (rk_agent_ips[i] != NULL) {
        snprintf(rk_buf, OS_SIZE_1024, "%s/%s", ROOTCHECK_DIR, agent);

        /* r+ to read and write. Do not truncate */
        rk_agent_fps[i] = fopen(rk_buf, "r+");
        if (!rk_agent_fps[i]) {
            /* Try opening with a w flag, file probably does not exist */
            rk_agent_fps[i] = fopen(rk_buf, "w");
            if (rk_agent_fps[i]) {
                fclose(rk_agent_fps[i]);
                rk_agent_fps[i] = fopen(rk_buf, "r+");
            }
        }
        if (!rk_agent_fps[i]) {
            merror(FOPEN_ERROR, rk_buf, errno, strerror(errno));

            free(rk_agent_ips[i]);
            rk_agent_ips[i] = NULL;
            w_mutex_unlock(&rootcheck_mutex[i]);
            return (NULL);
        }

        /* Return the opened pointer (the beginning of it) */
        fseek(rk_agent_fps[i], 0, SEEK_SET);
        *agent_id = i;
        return (rk_agent_fps[i]);
    } else {
        merror(MEM_ERROR, errno, strerror(errno));
        w_mutex_unlock(&rootcheck_mutex[i]);
        return (NULL);
    }
}

/* Special decoder for rootcheck
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
int DecodeRootcheck(Eventinfo *lf)
{
    int agent_id = 0;
    // long int scan_date;
    int result;

    char *tmpstr;
    char rk_buf[OS_SIZE_2048 + 1];

    FILE *fp;

    fpos_t fp_pos;

    /* Zero rk_buf */
    rk_buf[0] = '\0';
    rk_buf[OS_SIZE_2048] = '\0';

    fp = RK_File(lf->location, &agent_id);

    if (!fp) {
        merror("Error handling rootcheck database.");
        rk_err++;

        return (0);
    }

    /* Get initial position */
    if (fgetpos(fp, &fp_pos) == -1) {
        merror("Error handling rootcheck database (fgetpos).");
        w_mutex_unlock(&rootcheck_mutex[agent_id]);
        return (0);
    }

    /* Support to Wazuh DB */
    // if (!strcmp(lf->log, "Starting rootcheck scan."))
    //     scan_date = (long int)lf->time.tv_sec;

    result = QueryRootcheck(lf);
    switch (result) {
        case -1:
            merror("Error querying rootcheck database for agent %s", lf->agent_id);
            return 0;
        case 0:     // It exits
            result = SaveRootcheck(lf, 1);
            if (result < 0) {
                merror("Error updating rootcheck database for agent %s", lf->agent_id);
                return 0;
            }
            lf->alert = 0;  // No alert for existing entries
            break;
        case 1:     // It not exists
            result = SaveRootcheck(lf, 0);
            if (result < 0) {
                merror("Error storing rootcheck information for agent %s", lf->agent_id);
                return 0;
            }
            break;
        default:
            return 0;
    }

    /* Reads the file and search for a possible entry */
    while (fgets(rk_buf, OS_SIZE_2048 - 1, fp) != NULL) {
        /* Ignore blank lines and lines with a comment */
        if (rk_buf[0] == '\n' || rk_buf[0] == '#') {
            if (fgetpos(fp, &fp_pos) == -1) {
                merror("Error handling rootcheck database (fgetpos2).");
                w_mutex_unlock(&rootcheck_mutex[agent_id]);
                return (0);
            }
            continue;
        }

        /* Remove newline */
        tmpstr = strchr(rk_buf, '\n');
        if (tmpstr) {
            *tmpstr = '\0';
        }

        /* Old format without the time stamps */
        if (rk_buf[0] != '!') {
            /* Cannot use strncmp to avoid errors with crafted files */
            if (strcmp(lf->log, rk_buf) == 0) {
                fts_r = 0;
                lf->decoder_info = rootcheck_dec;
                lf->nfields = RK_NFIELDS;
                os_strdup(rootcheck_dec->fields[RK_TITLE], lf->fields[RK_TITLE].key);
                lf->fields[RK_TITLE].value = rk_get_title(lf->log);
                os_strdup(rootcheck_dec->fields[RK_FILE], lf->fields[RK_FILE].key);
                lf->fields[RK_FILE].value = rk_get_file(lf->log);
                w_mutex_unlock(&rootcheck_mutex[agent_id]);
                return (1);
            }
        }
        /* New format */
        else {
            /* Going past time: !1183431603!1183431603  (last, first seen) */
            tmpstr = rk_buf + 23;

            /* Matches, we need to upgrade last time saw */
            if (strcmp(lf->log, tmpstr) == 0) {
                if(fsetpos(fp, &fp_pos)) {
                    merror("Error handling rootcheck database (fsetpos).");
                    w_mutex_unlock(&rootcheck_mutex[agent_id]);
                    return (0);
                }
                fprintf(fp, "!%ld", (long int)lf->time.tv_sec);
                fflush(fp);
                fts_r = 0;
                lf->decoder_info = rootcheck_dec;
                lf->nfields = RK_NFIELDS;
                os_strdup(rootcheck_dec->fields[RK_TITLE], lf->fields[RK_TITLE].key);
                lf->fields[RK_TITLE].value = rk_get_title(lf->log);
                os_strdup(rootcheck_dec->fields[RK_FILE], lf->fields[RK_FILE].key);
                lf->fields[RK_FILE].value = rk_get_file(lf->log);
                w_mutex_unlock(&rootcheck_mutex[agent_id]);
                return (1);
            }
        }

        /* Get current position */
        if (fgetpos(fp, &fp_pos) == -1) {
            merror("Error handling rootcheck database (fgetpos3).");
            w_mutex_unlock(&rootcheck_mutex[agent_id]);
            return (0);
        }
    }

    /* Add the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp, "!%ld!%ld %s\n", (long int)lf->time.tv_sec, (long int)lf->time.tv_sec, lf->log);
    fflush(fp);

    fts_r = FTS_DONE;
    lf->decoder_info = rootcheck_dec;
    lf->rootcheck_fts = fts_r;
    lf->nfields = RK_NFIELDS;
    os_strdup(rootcheck_dec->fields[RK_TITLE], lf->fields[RK_TITLE].key);
    lf->fields[RK_TITLE].value = rk_get_title(lf->log);
    os_strdup(rootcheck_dec->fields[RK_FILE], lf->fields[RK_FILE].key);
    lf->fields[RK_FILE].value = rk_get_file(lf->log);

    w_mutex_unlock(&rootcheck_mutex[agent_id]);
    return (1);
}

int QueryRootcheck(Eventinfo *lf) {

    char * msg = NULL;
    char * response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s rootcheck query %s", lf->agent_id, lf->log);

    if (rk_send_db(msg, response) == 0) {
        if (!strcmp(response, "ok update")) {
            retval = 0;
        } else if (!strcmp(response, "ok insert")) {
            retval = 1;
        }
    }

    free(response);
    return retval;
}

int SaveRootcheck(Eventinfo *lf, int exists) {

    char * msg = NULL;
    char * response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    if (exists)
        snprintf(msg, OS_MAXSTR - 1, "agent %s rootcheck update %ld|%s", lf->agent_id, (long int)lf->time.tv_sec, lf->log);
    else
        snprintf(msg, OS_MAXSTR - 1, "agent %s rootcheck insert %ld|%s", lf->agent_id, (long int)lf->time.tv_sec, lf->log);

    if (rk_send_db(msg, response) == 0) {
        return 0;
    } else {
        return -1;
    }
}

int rk_send_db(char * msg, char * response) {
    static int sock = -1;
    ssize_t length;
    fd_set fdset;
    struct timeval timeout = {0, 1000};
    int size = strlen(msg);
    int retval = -1;
    static time_t last_attempt = 0;
    time_t mtime;

    // Connect to socket if disconnected

    if (sock < 0) {
        if (mtime = time(NULL), mtime > last_attempt + 10) {
            if (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
                last_attempt = mtime;
                merror("Unable to connect to socket '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                goto end;
            }
        } else {
            // Return silently
            goto end;
        }
    }

    // Send msg to Wazuh DB

    if (send(sock, msg, size + 1, MSG_DONTWAIT) < size) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            merror("Rootcheck decoder: database socket is full");
        } else if (errno == EPIPE) {
            if (mtime = time(NULL), mtime > last_attempt + 10) {
                // Retry to connect
                mwarn("Connection with wazuh-db lost. Reconnecting.");
                close(sock);

                if (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
                    last_attempt = mtime;
                    merror("Unable to connect to socket '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                    goto end;
                }

                if (send(sock, msg, size + 1, MSG_DONTWAIT) < size) {
                    last_attempt = mtime;
                    merror("at rk_send_db(): at send() (retry): %s (%d)", strerror(errno), errno);
                    goto end;
                }
            } else {
                // Return silently
                goto end;
            }

        } else {
            merror("at rk_send_db(): at send(): %s (%d)", strerror(errno), errno);
            goto end;
        }
    }

    // Wait for socket

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    if (select(sock + 1, &fdset, NULL, NULL, &timeout) < 0) {
        merror("at rk_send_db(): at select(): %s (%d)", strerror(errno), errno);
        goto end;
    }

    // Receive response from socket

    length = recv(sock, response, OS_MAXSTR, 0);

    switch (length) {
        case -1:
            merror("at rk_send_db(): at recv(): %s (%d)", strerror(errno), errno);
            goto end;

        default:

            if (strncmp(response, "ok", 2)) {
                merror("at rk_send_db(): received: '%s'", response);
                goto end;
            }
    }

    retval = 0;

end:
    free(msg);
    return retval;
}
