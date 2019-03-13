// Mar 8, 2019

#define ARGV0 "fluent"

/*
 * gcc -g -pipe -o fluent -I. -Iheaders -Iexternal/msgpack/include fluent.c -L. -lwazuh -lwazuhext
 */

#include <shared.h>
#include <os_net/os_net.h>
#include <msgpack.h>

#define WM_FLUENT_LOGTAG ARGV0 ":fluent-forwarder"

typedef struct wm_fluent_t {
    unsigned int enabled:1;
    char * tag;
    char * sock_path;
    char * address;
    unsigned short port;
    char * shared_pass;
    char * certificate;
    char * user_name;
    char * user_pass;
    int timeout;
    int client_sock;
} wm_fluent_t;

int wm_fluent_connect(wm_fluent_t * fluent) {
    char * ip;

    /* Close old connection */

    if (fluent->client_sock >= 0) {
        close(fluent->client_sock);
        fluent->client_sock = -1;
    }

    /* Resolve host name */

    ip = OS_GetHost(fluent->address, 5);
    if (!ip) {
        mterror(WM_FLUENT_LOGTAG, "Cannot resolve address '%s'", fluent->address);
        return -1;
    }

    /* Connect */

    fluent->client_sock = OS_ConnectTCP(fluent->port, ip, 0);
    free(ip);

    if (fluent->client_sock < 0) {
        mterror(WM_FLUENT_LOGTAG, "Cannot connect to '%s': %s (%d)", fluent->address, strerror(errno), errno);
        return -1;
    }

    /* Set timeout */

    if (fluent->timeout) {
        if (OS_SetSendTimeout(fluent->client_sock, fluent->timeout) < 0) {
            merror("Cannot set sending timeout to '%s': %s (%d)", fluent->address, strerror(errno), errno);
        }

        if (OS_SetRecvTimeout(fluent->client_sock, fluent->timeout, 0) < 0) {
            merror("Cannot set receiving timeout to '%s': %s (%d)", fluent->address, strerror(errno), errno);
        }
    }

    return 0;
}

int wm_fluent_handshake(wm_fluent_t * fluent) {
    /* Connect to address */

    if (wm_fluent_connect(fluent) < 0) {
        return -1;
    }

    if (fluent->shared_pass) {
        /* TLS mode */
    }

    return 0;
}

int wm_fluent_send(wm_fluent_t * fluent, const char * str, size_t size) {
    size_t taglen = strlen(fluent->tag);
    int retval;

    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);

    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&pk, 4);
    msgpack_pack_str(&pk, taglen);
    msgpack_pack_str_body(&pk, fluent->tag, taglen);
    msgpack_pack_unsigned_int(&pk, time(NULL));
    msgpack_pack_str(&pk, size);
    msgpack_pack_str_body(&pk, str, size);
    msgpack_pack_map(&pk, 1);
    msgpack_pack_str(&pk, 6);
    msgpack_pack_str_body(&pk, "option", 6);
    msgpack_pack_str(&pk, 8);
    msgpack_pack_str_body(&pk, "optional", 8);

    retval = send(fluent->client_sock, sbuf.data, sbuf.size, 0) == sbuf.size ? 0 : -1;

    msgpack_sbuffer_destroy(&sbuf);
    return retval;
}

int main() {
    int server_sock;
    char * buffer;
    ssize_t recv_b;

    // TODO: Remove
    signal(SIGPIPE, SIG_IGN);

    wm_fluent_t fluent = { 1, "debug.test", "/root/fluent.sock", "localhost", 24224, NULL, NULL, NULL, NULL, 10 };
    //wm_fluent_t fluent = { 1, "debug.test", "/root/fluent.sock", "localhost", 24225, NULL, NULL, NULL, NULL, 10 };

    /* Listen socket */
    server_sock = OS_BindUnixDomain(fluent.sock_path, SOCK_DGRAM, OS_MAXSTR);
    if (server_sock < 0) {
        mterror(WM_FLUENT_LOGTAG, "Unable to bind to socket '%s': (%d) %s.", WM_LOCAL_SOCK, errno, strerror(errno));
        pthread_exit(NULL);
    }

    while (wm_fluent_handshake(&fluent) < 0) {
        sleep(30);
    }

    mtinfo(WM_FLUENT_LOGTAG, "Connected to %s:%hu", fluent.address, fluent.port);
    os_malloc(OS_MAXSTR, buffer);

    /* Main loop */

    while (1) {
        recv_b = recv(server_sock, buffer, OS_MAXSTR - 1, 0);

        switch (recv_b) {
        case -1:
            mterror(WM_FLUENT_LOGTAG, "Cannot receive data from '%s': %s (%d)", fluent.sock_path, strerror(errno), errno);
            continue;
        case 0:
            mterror(WM_FLUENT_LOGTAG, "Empty string received from '%s'", fluent.sock_path);
            continue;
        default:
            if (wm_fluent_send(&fluent, buffer, recv_b) < 0) {
                mtwarn(WM_FLUENT_LOGTAG, "Cannot send data to '%s': %s (%d). Reconnecting...", fluent.address, strerror(errno), errno);

                while (wm_fluent_handshake(&fluent) < 0) {
                    sleep(30);
                }

                mtinfo(WM_FLUENT_LOGTAG, "Connected to %s:%hu", fluent.address, fluent.port);
                wm_fluent_send(&fluent, buffer, recv_b);
            }
        }
    }

    return EXIT_SUCCESS;
}
