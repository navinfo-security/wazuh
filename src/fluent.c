// Mar 8, 2019

#define ARGV0 "fluent"

/*
 * gcc -g -pipe -Wall -Wextra -o fluent -I. -Iheaders -Iexternal/msgpack/include fluent.c -L. -lwazuh -lwazuhext
 */

#include <shared.h>
#include <os_net/os_net.h>
#include <msgpack.h>
#include <openssl/ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define WM_FLUENT_LOGTAG ARGV0 ":fluent-forwarder"
#define REQUEST_SIZE 4096

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror_critical(msg, ...) _mterror_critical(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

#define expect_type(obj, t, str) if (obj.type != t) { mdebug2("Expecting %s", str); goto error; }
#define expect_string(obj, s) if (strncmp(obj.via.str.ptr, s, obj.via.str.size)) { mdebug2("Expecting string '%s'", s); goto error; }

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
    SSL_CTX * ctx;
    SSL * ssl;
    BIO * bio;
} wm_fluent_t;

typedef struct wm_fluent_helo_t {
    size_t nonce_size;
    char * nonce;
    size_t auth_size;
    char * auth;
    unsigned int keepalive:1;
} wm_fluent_helo_t;

char * wm_fluent_strdup(const msgpack_object_str * str) {
    char * string;
    os_malloc(str->size + 1, string);
    memcpy(string, str->ptr, str->size);
    string[str->size] = '\0';
    return string;
}

char * wm_fluent_bindup(const msgpack_object_bin * bin) {
    char * string;
    os_malloc(bin->size, string);
    memcpy(string, bin->ptr, bin->size);
    return string;
}

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
        merror("Cannot resolve address '%s'", fluent->address);
        return -1;
    }

    /* Connect */

    fluent->client_sock = OS_ConnectTCP(fluent->port, ip, 0);
    free(ip);

    if (fluent->client_sock < 0) {
        merror("Cannot connect to '%s': %s (%d)", fluent->address, strerror(errno), errno);
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

int wm_fluent_ssl_ctx(wm_fluent_t * fluent) {
    /* Free old context */

    if (fluent->ctx) {
        SSL_CTX_free(fluent->ctx);
    }

    /* Create context */

    fluent->ctx = SSL_CTX_new(TLS_method());
    if (!fluent->ctx) {
        merror("Cannot create a SSL context: %s", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    /* Load CA certificate, if defined */

    if (fluent->certificate) {
        if (fluent->certificate && !SSL_CTX_load_verify_locations(fluent->ctx, fluent->certificate, NULL)) {
            merror("Unable to read CA certificate file '%s': %s", fluent->certificate, ERR_reason_error_string(ERR_get_error()));
            return -1;
        }

        SSL_CTX_set_verify(fluent->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }

    return 0;
}

int wm_fluent_ssl_connect(wm_fluent_t * fluent) {
    assert(fluent);
    assert(fluent->client_sock >= 0);

    if (fluent->ssl) {
        SSL_free(fluent->ssl);
        fluent->ssl = NULL;
    }

    /* Get context */

    if (wm_fluent_ssl_ctx(fluent) < 0) {
        return -1;
    }

    /* Initialize structures */

    fluent->ssl = SSL_new(fluent->ctx);
    if (!fluent->ssl) {
        merror("Cannot create SSL structure: %s", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    fluent->bio = BIO_new_socket(fluent->client_sock, 0);
    if (!fluent->bio) {
        merror("Cannot bind SSL to socket: %s", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    SSL_set_bio(fluent->ssl, fluent->bio, fluent->bio);

    /* SSL handshake */

    switch (SSL_connect(fluent->ssl)) {
    case 0:
        mwarn("Cannot connect to '%s': %s", fluent->address, ERR_reason_error_string(ERR_get_error()));
        return -1;
    case 1:
        return 0;
    default:
        merror("Cannot connect to '%s': %s", fluent->address, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
}

void wm_fluent_helo_free(wm_fluent_helo_t * helo) {
    if (helo) {
        free(helo->nonce);
        free(helo->auth);
        free(helo);
    }
}

int wm_fluent_recv(wm_fluent_t * fluent, msgpack_unpacker * unp) {
    int read_b;

    assert(unp);

    /* Extend buffer if needed */

    if (msgpack_unpacker_buffer_capacity(unp) < REQUEST_SIZE && !msgpack_unpacker_reserve_buffer(unp, REQUEST_SIZE)) {
        merror_exit("Cannot extend memory for unpacker.");
    }

    /* Receive data */

    read_b = SSL_read(fluent->ssl, msgpack_unpacker_buffer(unp), 4096);
    if (read_b < 0) {
        mterror("Connection error with '%s': %s", fluent->address, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    msgpack_unpacker_buffer_consumed(unp, read_b);
    return read_b;
}

int wm_fluent_unpack(wm_fluent_t * fluent, msgpack_unpacker * unp, msgpack_unpacked * result) {
    msgpack_unpacked_init(result);

    if (wm_fluent_recv(fluent, unp) < 0) {
        return -1;
    }

    if (msgpack_unpacker_next(unp, result) != MSGPACK_UNPACK_SUCCESS) {
        merror("Invalid data received from the server.");
        return -1;
    }

    return 0;
}

wm_fluent_helo_t * wm_fluent_recv_helo(wm_fluent_t * fluent) {
    msgpack_unpacker unp;
    msgpack_unpacked result;
    wm_fluent_helo_t * helo;
    msgpack_object * array;
    msgpack_object_kv * map;
    unsigned int i;

    if (!msgpack_unpacker_init(&unp, 4096)) {
        merror_exit("Cannot allocate memory for unpacker.");
    }

    if (wm_fluent_unpack(fluent, &unp, &result)) {
        return NULL;
    }

    os_calloc(1, sizeof(wm_fluent_helo_t), helo);
    /* If keepalive is not defined, the default value is true */
    helo->keepalive = 1;

    msgpack_object_print(stdout, result.data);
    printf("\n");

    /* Parse HELO message pack */

    expect_type(result.data, MSGPACK_OBJECT_ARRAY, "array");

    if (result.data.via.array.size < 2) {
        mdebug2("Expecting binary array");
        goto error;
    }

    array = result.data.via.array.ptr;

    expect_type(array[0], MSGPACK_OBJECT_STR, "string");

    /* Strings are not null-terminated! */

    expect_string(array[0], "HELO");
    expect_type(array[1], MSGPACK_OBJECT_MAP, "map");

    map = array[1].via.map.ptr;

    for (i = 0; i < array[1].via.map.size; ++i) {
        expect_type(map[i].key, MSGPACK_OBJECT_STR, "string key");

        if (strncmp(map[i].key.via.str.ptr, "nonce", map[i].key.via.str.size) == 0) {
            /* 'nonce' may be either string or binary */

            switch (map[i].val.type) {
            case MSGPACK_OBJECT_STR:
                helo->nonce_size = map[i].val.via.str.size;
                free(helo->nonce);
                helo->nonce = wm_fluent_strdup(&map[i].val.via.str);
                break;

            case MSGPACK_OBJECT_BIN:
                helo->nonce_size = map[i].val.via.bin.size;
                free(helo->nonce);
                helo->nonce = wm_fluent_bindup(&map[i].val.via.bin);
                break;

            default:
                mdebug2("Expecting string or binary value for nonce");
                goto error;
            }
        } else if (strncmp(map[i].key.via.str.ptr, "auth", map[i].key.via.str.size) == 0) {
            /* 'auth' may be either string or binary */

            switch (map[i].val.type) {
            case MSGPACK_OBJECT_STR:
                helo->auth_size = map[i].val.via.str.size;
                free(helo->auth);
                helo->auth = wm_fluent_strdup(&map[i].val.via.str);
                break;

            case MSGPACK_OBJECT_BIN:
                helo->auth_size = map[i].val.via.bin.size;
                free(helo->auth);
                helo->auth = wm_fluent_bindup(&map[i].val.via.bin);
                break;

            default:
                mdebug2("Expecting string or binary value for auth");
                goto error;
            }
        } else if (strncmp(map[i].key.via.str.ptr, "keepalive", map[i].key.via.str.size) == 0) {
            expect_type(map[i].val, MSGPACK_OBJECT_BOOLEAN, "boolean value");
            helo->keepalive = map[i].val.via.boolean;
        } else {
            mdebug2("Unexpected key: %.*s", map[i].key.via.str.size, map[i].key.via.str.ptr);
        }
    }

    goto end;

error:

    wm_fluent_helo_free(helo);
    helo = NULL;

end:
    msgpack_unpacker_destroy(&unp);
    return helo;
}

int wm_fluent_handshake(wm_fluent_t * fluent) {
    wm_fluent_helo_t * helo;

    /* Connect to address */

    if (wm_fluent_connect(fluent) < 0) {
        return -1;
    }

    if (fluent->shared_pass) {
        /* TLS mode */

        if (wm_fluent_ssl_connect(fluent) < 0) {
            return -1;
        }

        mdebug1("Connection with %s:%hu established", fluent->address, fluent->port);

        /* Fluent protocol handshake */

        helo = wm_fluent_recv_helo(fluent);

        if (!helo) {
            merror("Cannot receive HELO message from server");
            return -1;
        }

        wm_fluent_helo_free(helo);
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

    retval = send(fluent->client_sock, sbuf.data, sbuf.size, 0) == (ssize_t)sbuf.size ? 0 : -1;

    msgpack_sbuffer_destroy(&sbuf);
    return retval;
}

int main() {
    int server_sock;
    char * buffer;
    ssize_t recv_b;

    // TODO: Remove
    signal(SIGPIPE, SIG_IGN);
    nowDebug();
    nowDebug();

    mdebug2("Module started");

    // TODO: Set up in the config function
    SSL_load_error_strings();
    SSL_library_init();

    //wm_fluent_t fluent = { 1, "debug.test", "/root/fluent.sock", "localhost", 24224, NULL, NULL, NULL, NULL, 10, -1, NULL, NULL, NULL };
    wm_fluent_t fluent = { 1, "debug.test", "/root/fluent.sock", "localhost", 24225, "secret_string", "/root/conf/fluentd.crt", NULL, NULL, 10 , -1, NULL, NULL, NULL };

    /* Listen socket */
    server_sock = OS_BindUnixDomain(fluent.sock_path, SOCK_DGRAM, OS_MAXSTR);
    if (server_sock < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.", WM_LOCAL_SOCK, errno, strerror(errno));
        return EXIT_FAILURE;
    }

    while (wm_fluent_handshake(&fluent) < 0) {
        mdebug2("Handshake failed. Waiting 30 seconds.");
        sleep(30);
    }

    minfo("Connected to %s:%hu", fluent.address, fluent.port);
    os_malloc(OS_MAXSTR, buffer);

    /* Main loop */

    while (1) {
        recv_b = recv(server_sock, buffer, OS_MAXSTR - 1, 0);

        switch (recv_b) {
        case -1:
            merror("Cannot receive data from '%s': %s (%d)", fluent.sock_path, strerror(errno), errno);
            continue;
        case 0:
            merror("Empty string received from '%s'", fluent.sock_path);
            continue;
        default:
            if (wm_fluent_send(&fluent, buffer, recv_b) < 0) {
                mwarn("Cannot send data to '%s': %s (%d). Reconnecting...", fluent.address, strerror(errno), errno);

                while (wm_fluent_handshake(&fluent) < 0) {
                    sleep(30);
                }

                minfo("Connected to %s:%hu", fluent.address, fluent.port);
                wm_fluent_send(&fluent, buffer, recv_b);
            }
        }
    }

    return EXIT_SUCCESS;
}
