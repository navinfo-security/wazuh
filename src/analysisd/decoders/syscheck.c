/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

// Syscheck decoder

#include "eventinfo.h"
#include "os_regex/os_regex.h"
#include "config.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "syscheck_op.h"
#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"

static int fim_send_db(char * msg, char * response);
static void check_diff (sk_sum_t oldsum, sk_sum_t newsum, Eventinfo *l, const char *f_name);

// Compare the first common fields between sum strings
static int SumCompare(const char *s1, const char *s2);

// Initialize the necessary information to process the syscheck information
void SyscheckInit()
{
    int i = 0;

    sdb.db_err = 0;

    for (; i <= MAX_AGENTS; i++) {
        sdb.agent_ips[i] = NULL;
        sdb.agent_fps[i] = NULL;
        sdb.agent_cp[i][0] = '0';
    }

    // Clear db memory
    memset(sdb.buf, '\0', OS_MAXSTR + 1);
    memset(sdb.comment, '\0', OS_MAXSTR + 1);

    memset(sdb.size, '\0', OS_FLSIZE + 1);
    memset(sdb.perm, '\0', OS_FLSIZE + 1);
    memset(sdb.owner, '\0', OS_FLSIZE + 1);
    memset(sdb.gowner, '\0', OS_FLSIZE + 1);
    memset(sdb.md5, '\0', OS_FLSIZE + 1);
    memset(sdb.sha1, '\0', OS_FLSIZE + 1);
    memset(sdb.sha256, '\0', OS_FLSIZE + 1);
    memset(sdb.mtime, '\0', OS_FLSIZE + 1);
    memset(sdb.inode, '\0', OS_FLSIZE + 1);

    // Create decoder
    os_calloc(1, sizeof(OSDecoderInfo), sdb.syscheck_dec);
    sdb.syscheck_dec->id = getDecoderfromlist(SYSCHECK_MOD);
    sdb.syscheck_dec->name = SYSCHECK_MOD;
    sdb.syscheck_dec->type = OSSEC_RL;
    sdb.syscheck_dec->fts = 0;

    os_calloc(Config.decoder_order_size, sizeof(char *), sdb.syscheck_dec->fields);
    sdb.syscheck_dec->fields[SK_FILE] = "file";
    sdb.syscheck_dec->fields[SK_SIZE] = "size";
    sdb.syscheck_dec->fields[SK_PERM] = "perm";
    sdb.syscheck_dec->fields[SK_UID] = "uid";
    sdb.syscheck_dec->fields[SK_GID] = "gid";
    sdb.syscheck_dec->fields[SK_MD5] = "md5";
    sdb.syscheck_dec->fields[SK_SHA1] = "sha1";
    sdb.syscheck_dec->fields[SK_SHA256] = "sha256";
    sdb.syscheck_dec->fields[SK_UNAME] = "uname";
    sdb.syscheck_dec->fields[SK_GNAME] = "gname";
    sdb.syscheck_dec->fields[SK_INODE] = "inode";

    sdb.id1 = getDecoderfromlist(SYSCHECK_MOD);
    sdb.id2 = getDecoderfromlist(SYSCHECK_MOD2);
    sdb.id3 = getDecoderfromlist(SYSCHECK_MOD3);
    sdb.idn = getDecoderfromlist(SYSCHECK_NEW);
    sdb.idd = getDecoderfromlist(SYSCHECK_DEL);

    mdebug1("SyscheckInit completed.");
}

// Search the DB for any entry related to the file being received
static int DB_Search(const char *f_name, char *c_sum, Eventinfo *lf)
{
    sk_sum_t oldsum;
    sk_sum_t newsum;
    int changes = 0;
    char * saved_sum = NULL;
    char *msg = NULL;
    char *response = NULL;
    char *c_sumcp = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    os_strdup(c_sum, c_sumcp);

    // Find row in SQLite DB
    snprintf(msg, OS_MAXSTR - 1, "agent %s syscheck load", lf->agent_id);
    wm_strcat(&msg, f_name, ' ');

    if (fim_send_db(msg, response) < 0) {
        lf->data = NULL;
        free (msg);
        free (response);
        free (c_sumcp);
        return -1;
    }
    minfo("~~~~ Call:'%s' response:'%s'", msg, response);

    if(saved_sum = strchr(response, ' '), saved_sum) {
        *saved_sum++ = '\0';
    }
    else {
        //error format msg
    }

    //check si el numero de cambios supera el limite en el intervalo de tiempo dado.

    if (strcmp(response, "ok") == 0) {
        if(saved_sum = strchr(saved_sum, ':'), saved_sum) {
            minfo("~~~~ --modified, readded-- c_sum:'%s' saved_sum:'%s' changes:'%d'", c_sum, saved_sum, changes);
            //modified or readded
            changes = atoi(saved_sum);
            saved_sum = strchr(saved_sum, ':');
            *saved_sum++ = '\0';

            if (SumCompare(saved_sum, c_sum) == 0) {
                minfo("~~~~ No diff, return without alert");
                lf->data = NULL;
                free (msg);
                free (response);
                free (c_sumcp);
                return(0);
            }
            else {
                switch (sk_decode_sum(&newsum, c_sum)) {
                    case -1:
                        merror("Couldn't decode syscheck sum from log.");
                        break;

                    case 0: //if modified, readded
                        sk_fill_event(lf, f_name, &newsum);
                        *msg = '\0';
                        *response = '\0';
                        snprintf(msg, OS_MAXSTR - 1, "agent %s syscheck save", lf->agent_id);
                        wm_strcat(&msg, "file", ' ');
                        wm_strcat(&msg, c_sumcp, ' ');
                        wm_strcat(&msg, f_name, ' ');

                        //minfo("~~~~ Call to save msg:'%s'", msg);
                        if (fim_send_db(msg, response) < 0) {
                            merror("at FIM DB_Search(): %s", response);
                            lf->data = NULL;
                            free (msg);
                            free (response);
                            free (c_sumcp);
                            return -1;
                        }
                        //minfo("~~~~ Call to save response:'%s'", response);
                        switch (sk_decode_sum(&oldsum, saved_sum)) {
                            case -1:
                                merror("Couldn't decode syscheck sum from log.");
                                break;

                            case 0:
                                minfo("~~~~ alert FIM_MODIFIED: %s", f_name);
                                sdb.syscheck_dec->id = sdb.id1;
                                lf->event_type = FIM_MODIFIED;
                                break;

                            case 1:
                                minfo("~~~~ alert FIM_READDED: %s", f_name);
                                sdb.syscheck_dec->id = sdb.idn;
                                lf->event_type = FIM_READDED;
                                break;
                        }
                        //Check changes
                        check_diff (oldsum, newsum, lf, f_name);
                        break;

                    case 1: //if deleted
                        sk_fill_event(lf, f_name, &newsum);
                        *msg = '\0';
                        *response = '\0';
                        snprintf(msg, OS_MAXSTR - 1, "agent %s syscheck delete", lf->agent_id);
                        wm_strcat(&msg, "file", ' ');
                        wm_strcat(&msg, f_name, ' ');

                        if (fim_send_db(msg, response) < 0) {
                            merror("at FIM DB_Search(): %s", response);
                            lf->data = NULL;
                            free (msg);
                            free (response);
                            free (c_sumcp);
                            return -1;
                        }
                        minfo("~~~~ alert FIM_DELETED: %s", f_name);
                        snprintf(sdb.comment, OS_MAXSTR,
                                "File '%.756s' was deleted. Unable to retrieve checksum.", f_name);
                        sdb.syscheck_dec->id = sdb.idd;
                        lf->event_type = FIM_DELETED;
                        break;
                }
            }
        }
        else {
            //add
            minfo("~~~~ --added-- c_sum:'%s' saved_sum:'%s' changes:'%d'", c_sum, saved_sum, changes);
            sk_decode_sum(&newsum, c_sum);
            sk_fill_event(lf, f_name, &newsum);
            *msg = '\0';
            *response = '\0';
            snprintf(msg, OS_MAXSTR - 1, "agent %s syscheck save", lf->agent_id);
            wm_strcat(&msg, "file", ' ');
            wm_strcat(&msg, c_sumcp, ' ');
            wm_strcat(&msg, f_name, ' ');

            //minfo("~~~~ Call to save msg:'%s'", msg);
            if (fim_send_db(msg, response) < 0) {
                merror("at FIM DB_Search(): %s", response);
                lf->data = NULL;
                free (msg);
                free (response);
                free (c_sumcp);
                return -1;
            }
            sdb.syscheck_dec->id = sdb.idn;
            lf->event_type = FIM_ADDED;

            /* New file message */
            snprintf(sdb.comment, OS_MAXSTR,
                    "New file '%.756s' added to the file system.", f_name);
        }
    }
    else {
        merror("at Syscheck decoder DB_Search(): %s", response);
        lf->data = NULL;
        free (msg);
        free (response);
        free (c_sumcp);
        return(0);
    }
    /* Create a new log message */
    free(lf->full_log);
    os_strdup(sdb.comment, lf->full_log);
    lf->log = lf->full_log;

    /* Set decoder */
    lf->decoder_info = sdb.syscheck_dec;

    free (msg);
    free (response);
    free (c_sumcp);
    return (1);
}

/* Special decoder for syscheck
 * Not using the default decoding lib for simplicity
 * and to be less resource intensive
*/
int DecodeSyscheck(Eventinfo *lf)
{
    char *c_sum;
    char *f_name;

    // Every syscheck message must be in the following format: checksum filename
    f_name = strchr(lf->log, ' ');
    if (f_name == NULL) {

        /* If we don't have a valid syscheck message, it may be
         * a database completed message
         */
        if (strcmp(lf->log, HC_SK_DB_COMPLETED) == 0) {
            //DB_SetCompleted(lf);
            return (0);
        }

        merror(SK_INV_MSG);
        return (0);
    }

    // Zero to get the check sum
    *f_name = '\0';
    f_name++;

    // Get diff
    lf->data = strchr(f_name, '\n');
    if (lf->data) {
        *lf->data = '\0';
        lf->data++;
    } else {
        lf->data = NULL;
    }

    // Check if file is supposed to be ignored
    if (Config.syscheck_ignore) {
        char **ff_ig = Config.syscheck_ignore;

        while (*ff_ig) {
            if (strncasecmp(*ff_ig, f_name, strlen(*ff_ig)) == 0) {
                lf->data = NULL;
                return (0);
            }

            ff_ig++;
        }
    }

    // Checksum is at the beginning of the log
    c_sum = lf->log;

    // Search for file changes
    return (DB_Search(f_name, c_sum, lf));
}

// Compare the first common fields between sum strings
int SumCompare(const char *s1, const char *s2) {
    const char *ptr1 = strchr(s1, ':');
    const char *ptr2 = strchr(s2, ':');
    size_t size1;
    size_t size2;

    while (ptr1 && ptr2) {
        ptr1 = strchr(ptr1 + 1, ':');
        ptr2 = strchr(ptr2 + 1, ':');
    }

    size1 = ptr1 ? (size_t)(ptr1 - s1) : strlen(s1);
    size2 = ptr2 ? (size_t)(ptr2 - s2) : strlen(s2);

    return size1 == size2 ? strncmp(s1, s2, size1) : 1;
}

static int fim_send_db(char * msg, char * response) {
    static int sock = -1;
    ssize_t length;
    fd_set fdset;
    struct timeval timeout = {0, 1000};
    int size = strlen(msg);
    static time_t last_attempt = 0;
    time_t mtime;

    // Connect to socket if disconnected

    if (sock < 0) {
        if (mtime = time(NULL), mtime > last_attempt + 10) {
            if (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
                last_attempt = mtime;
                merror("Unable to connect to socket '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                return (-1);
            }
        } else {
            // Return silently
            return (-1);
        }
    }

    // Send msg to Wazuh DB

    if (send(sock, msg, size + 1, MSG_DONTWAIT) < size) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            merror("FIM decoder: database socket is full");
        } else if (errno == EPIPE) {
            if (mtime = time(NULL), mtime > last_attempt + 10) {
                // Retry to connect
                mwarn("Connection with wazuh-db lost. Reconnecting.");
                close(sock);

                if (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
                    last_attempt = mtime;
                    merror("Unable to connect to socket '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                    return (-1);
                }

                if (send(sock, msg, size + 1, MSG_DONTWAIT) < size) {
                    last_attempt = mtime;
                    merror("at fim_send_db(): at send() (retry): %s (%d)", strerror(errno), errno);
                    return (-1);
                }
            } else {
                // Return silently
                return (-1);
            }

        } else {
            merror("at fim_send_db(): at send(): %s (%d)", strerror(errno), errno);
            return (-1);
        }
    }

    // Wait for socket

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    if (select(sock + 1, &fdset, NULL, NULL, &timeout) < 0) {
        merror("at fim_send_db(): at select(): %s (%d)", strerror(errno), errno);
        return (-1);
    }

    // Receive response from socket
    length = recv(sock, response, OS_MAXSTR, 0);
    if (length < 0) {
        merror("at fim_send_db(): at recv(): %s (%d)", strerror(errno), errno);
        return (-1);
    }

    return (0);
}

static void check_diff (sk_sum_t oldsum, sk_sum_t newsum, Eventinfo *lf, const char *f_name) {
    /* Generate size message */
    if (strcmp(oldsum.size, newsum.size) == 0) {
        sdb.size[0] = '\0';
    } else {
        snprintf(sdb.size, OS_FLSIZE,
                    "Size changed from '%s' to '%s'\n",
                    oldsum.size, newsum.size);

        os_strdup(oldsum.size, lf->size_before);
    }

    /* Permission message */
    if (oldsum.perm == newsum.perm) {
        sdb.perm[0] = '\0';
    } else if (oldsum.perm > 0 && newsum.perm > 0) {
        char opstr[10];
        char npstr[10];

        strncpy(opstr, agent_file_perm(oldsum.perm), sizeof(opstr) - 1);
        strncpy(npstr, agent_file_perm(newsum.perm), sizeof(npstr) - 1);
        opstr[9] = npstr[9] = '\0';

        snprintf(sdb.perm, OS_FLSIZE, "Permissions changed from "
                    "'%9.9s' to '%9.9s'\n", opstr, npstr);

        lf->perm_before = oldsum.perm;
    }

    /* Ownership message */
    if (strcmp(newsum.uid, oldsum.uid) == 0) {
        sdb.owner[0] = '\0';
    } else {
        if (oldsum.uname && newsum.uname) {
            snprintf(sdb.owner, OS_FLSIZE, "Ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum.uname, oldsum.uid, newsum.uname, newsum.uid);
            os_strdup(oldsum.uname, lf->uname_before);
        } else
            snprintf(sdb.owner, OS_FLSIZE, "Ownership was '%s', "
                        "now it is '%s'\n",
                        oldsum.uid, newsum.uid);

        os_strdup(oldsum.uid, lf->owner_before);
    }

    /* Group ownership message */
    if (strcmp(newsum.gid, oldsum.gid) == 0) {
        sdb.gowner[0] = '\0';
    } else {
        if (oldsum.gname && newsum.gname) {
            snprintf(sdb.owner, OS_FLSIZE, "Group ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum.gname, oldsum.gid, newsum.gname, newsum.gid);
            os_strdup(oldsum.gname, lf->gname_before);
        } else
            snprintf(sdb.gowner, OS_FLSIZE, "Group ownership was '%s', "
                        "now it is '%s'\n",
                        oldsum.gid, newsum.gid);

        os_strdup(oldsum.gid, lf->gowner_before);
    }

    /* MD5 message */
    if (strcmp(newsum.md5, oldsum.md5) == 0) {
        sdb.md5[0] = '\0';
    } else {
        snprintf(sdb.md5, OS_FLSIZE, "Old md5sum was: '%s'\n"
                    "New md5sum is : '%s'\n",
                    oldsum.md5, newsum.md5);
        os_strdup(oldsum.md5, lf->md5_before);
    }

    /* SHA-1 message */
    if (strcmp(newsum.sha1, oldsum.sha1) == 0) {
        sdb.sha1[0] = '\0';
    } else {
        snprintf(sdb.sha1, OS_FLSIZE, "Old sha1sum was: '%s'\n"
                    "New sha1sum is : '%s'\n",
                    oldsum.sha1, newsum.sha1);
        os_strdup(oldsum.sha1, lf->sha1_before);
    }

    /* SHA-256 message */
    if(newsum.sha256 && oldsum.sha256)
    {
        if (strcmp(newsum.sha256, oldsum.sha256) == 0) {
            sdb.sha256[0] = '\0';
        } else {
            snprintf(sdb.sha256, OS_FLSIZE, "Old sha256sum was: '%s'\n"
                    "New sha256sum is : '%s'\n",
                    oldsum.sha256, newsum.sha256);
            os_strdup(oldsum.sha256, lf->sha256_before);
        }
    }

    /* Modification time message */
    if (oldsum.mtime && newsum.mtime && oldsum.mtime != newsum.mtime) {
        char *old_ctime = strdup(ctime(&oldsum.mtime));
        char *new_ctime = strdup(ctime(&newsum.mtime));
        old_ctime[strlen(old_ctime) - 1] = '\0';
        new_ctime[strlen(new_ctime) - 1] = '\0';

        snprintf(sdb.mtime, OS_FLSIZE, "Old modification time was: '%s', now it is '%s'\n", old_ctime, new_ctime);
        lf->mtime_before = oldsum.mtime;
        free(old_ctime);
        free(new_ctime);
    } else {
        sdb.mtime[0] = '\0';
    }

    /* Inode message */
    if (oldsum.inode && newsum.inode && oldsum.inode != newsum.inode) {
        snprintf(sdb.mtime, OS_FLSIZE, "Old inode was: '%ld', now it is '%ld'\n", oldsum.inode, newsum.inode);
        lf->inode_before = oldsum.inode;
    } else {
        sdb.inode[0] = '\0';
    }

    /* Provide information about the file */
    snprintf(sdb.comment, OS_MAXSTR, "Integrity checksum changed for: "
            "'%.756s'\n%s%s%s%s%s%s%s%s",
            f_name,
            sdb.size,
            sdb.perm,
            sdb.owner,
            sdb.gowner,
            sdb.md5,
            sdb.sha1,
            lf->data ? "What changed:\n" : "",
            lf->data ? lf->data : ""
    );

    if (lf->data) {
        os_strdup(lf->data, lf->diff);
    }
}