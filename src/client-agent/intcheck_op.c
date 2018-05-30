/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"


/* Send integrity checking information about a file to the server */
int intcheck_file(const char *file_name, const char *dir)
{
    struct stat statbuf;
    os_md5 mf_sum;
    os_sha1 sf_sum;
    os_sha256 sf256_sum;
    char newsum[PATH_MAX+4];

    strncpy(mf_sum,  "xxx", 4);
    strncpy(sf_sum,  "xxx", 4);
    strncpy(sf256_sum, "xxx", 4);

    newsum[0] = '\0';
    newsum[1172] = '\0';

    /* Stat the file */
#ifdef WIN32
    if (stat(file_name, &statbuf) < 0)
#else
    if (lstat(file_name, &statbuf) < 0)
#endif
    {
        snprintf(newsum, sizeof(newsum), "%c:%s:-1 %s%s", SYSCHECK_MQ, SYSCHECK,
                 dir, file_name);
        send_msg(newsum, -1);

        return (1);
    }

    /* Generate new checksum */
#ifdef WIN32
    if (S_ISREG(statbuf.st_mode))
#else
    if (S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
#endif
    {
        if (OS_MD5_SHA1_SHA256_File(file_name, NULL, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0)
        {
            strncpy(mf_sum, "n/a", 4);
            strncpy(sf_sum, "n/a", 4);
            strncpy(sf256_sum, "n/a", 4);
        }
    }
    

    snprintf(newsum, sizeof(newsum), "%c:%s:%d:%d:%d:%d:%s:%s:%s %s%s",
            SYSCHECK_MQ,
            SYSCHECK,
            (int)statbuf.st_size,
            (int)statbuf.st_mode,
            (int)statbuf.st_uid,
            (int)statbuf.st_gid,
            mf_sum,
            sf_sum,
            sf256_sum,
            dir, 
            file_name);

    send_msg(newsum, -1);
    return (1);
}
