/* Remoted profiling thread
 * Copyright (C) 2017 Wazuh Inc.
 * November 16, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>

#define RP_VAL(tm, c) tm, c, c ? tm / c : 0

static int rp_interval;

static double rp_loop_tm;
static double rp_recv_tm;
static double rp_recv_tcp1_tm;
static double rp_recv_tcp2_tm;
static double rp_handle_secure_tm;
static double rp_reload_keys_tm;
static double rp_read_sec_msg_tm;
static double rp_save_control_msg_tm;
static double rp_write_file_tm;
static double rp_msg_enqueue_tm;
static double rp_send_tm;

static int rp_loop_c;
static int rp_recv_c;
static int rp_recv_tcp1_c;
static int rp_recv_tcp2_c;
static int rp_handle_secure_c;
static int rp_reload_keys_c;
static int rp_read_sec_msg_c;
static int rp_save_control_msg_c;
static int rp_write_file_c;
static int rp_msg_enqueue_c;
static int rp_send_c;

static const char * REPORT_STR = "Last %d seconds:\n\
                                 accum   count         average\n\
    loop:              %12.3f ms%8d%12.3f ms/\n\
    recv():            %12.3f ms%8d%12.3f ms/\n\
    recv_tcp1():       %12.3f ms%8d%12.3f ms/\n\
    recv_tcp2():       %12.3f ms%8d%12.3f ms/\n\
    handle_secure():   %12.3f ms%8d%12.3f ms/\n\
    reload_keys():     %12.3f ms%8d%12.3f ms/\n\
    read_sec_msg():    %12.3f ms%8d%12.3f ms/\n\
    save_control_msg():%12.3f ms%8d%12.3f ms/\n\
    write_file():      %12.3f ms%8d%12.3f ms/\n\
    msg_enqueue():     %12.3f ms%8d%12.3f ms/\n\
    send():            %12.3f ms%8d%12.3f ms/\n";

void * rprof_main(__attribute__((unused)) void * args) {
    double _rp_loop_tm;
    double _rp_recv_tm;
    double _rp_recv_tcp1_tm;
    double _rp_recv_tcp2_tm;
    double _rp_handle_secure_tm;
    double _rp_reload_keys_tm;
    double _rp_read_sec_msg_tm;
    double _rp_save_control_msg_tm;
    double _rp_write_file_tm;
    double _rp_msg_enqueue_tm;
    double _rp_send_tm;

    int _rp_loop_c;
    int _rp_recv_c;
    int _rp_recv_tcp1_c;
    int _rp_recv_tcp2_c;
    int _rp_handle_secure_c;
    int _rp_reload_keys_c;
    int _rp_read_sec_msg_c;
    int _rp_save_control_msg_c;
    int _rp_write_file_c;
    int _rp_msg_enqueue_c;
    int _rp_send_c;

    while (1) {
        sleep(rp_interval);

        _rp_loop_tm = rp_loop_tm * 1000;
        rp_loop_tm = 0;
        _rp_recv_tm = rp_recv_tm * 1000;
        rp_recv_tm = 0;
        _rp_recv_tcp1_tm = rp_recv_tcp1_tm * 1000;
        rp_recv_tcp1_tm = 0;
        _rp_recv_tcp2_tm = rp_recv_tcp2_tm * 1000;
        rp_recv_tcp2_tm = 0;
        _rp_handle_secure_tm = rp_handle_secure_tm * 1000;
        rp_handle_secure_tm = 0;
        _rp_reload_keys_tm = rp_reload_keys_tm * 1000;
        rp_reload_keys_tm = 0;
        _rp_read_sec_msg_tm = rp_read_sec_msg_tm * 1000;
        rp_read_sec_msg_tm = 0;
        _rp_save_control_msg_tm = rp_save_control_msg_tm * 1000;
        rp_save_control_msg_tm = 0;
        _rp_write_file_tm = rp_write_file_tm * 1000;
        rp_write_file_tm = 0;
        _rp_msg_enqueue_tm = rp_msg_enqueue_tm * 1000;
        rp_msg_enqueue_tm = 0;
        _rp_send_tm = rp_send_tm * 1000;
        rp_send_tm = 0;

        _rp_loop_c = rp_loop_c;
        rp_loop_c = 0;
        _rp_recv_c = rp_recv_c;
        rp_recv_c = 0;
        _rp_recv_tcp1_c = rp_recv_tcp1_c;
        rp_recv_tcp1_c = 0;
        _rp_recv_tcp2_c = rp_recv_tcp2_c;
        rp_recv_tcp2_c = 0;
        _rp_handle_secure_c = rp_handle_secure_c;
        rp_handle_secure_c = 0;
        _rp_reload_keys_c = rp_reload_keys_c;
        rp_reload_keys_c = 0;
        _rp_read_sec_msg_c = rp_read_sec_msg_c;
        rp_read_sec_msg_c = 0;
        _rp_save_control_msg_c = rp_save_control_msg_c;
        rp_save_control_msg_c = 0;
        _rp_write_file_c = rp_write_file_c;
        rp_write_file_c = 0;
        _rp_msg_enqueue_c = rp_msg_enqueue_c;
        rp_msg_enqueue_c = 0;
        _rp_send_c = rp_send_c;
        rp_send_c = 0;

        mprofile(REPORT_STR, rp_interval,
            RP_VAL(_rp_loop_tm, _rp_loop_c),
            RP_VAL(_rp_recv_tm, _rp_recv_c),
            RP_VAL(_rp_recv_tcp1_tm, _rp_recv_tcp1_c),
            RP_VAL(_rp_recv_tcp2_tm, _rp_recv_tcp2_c),
            RP_VAL(_rp_handle_secure_tm, _rp_handle_secure_c),
            RP_VAL(_rp_reload_keys_tm, _rp_reload_keys_c),
            RP_VAL(_rp_read_sec_msg_tm, _rp_read_sec_msg_c),
            RP_VAL(_rp_save_control_msg_tm, _rp_save_control_msg_c),
            RP_VAL(_rp_write_file_tm, _rp_write_file_c),
            RP_VAL(_rp_msg_enqueue_tm, _rp_msg_enqueue_c),
            RP_VAL(_rp_send_tm, _rp_send_c));
    }

    return NULL;
}

void rprof_set_interval(int interval) {
    rp_interval = interval;
}

int rprof_get_interval() {
    return rp_interval;
}

void rprof_loop(double t) {
    rp_loop_tm += t;
    rp_loop_c++;
}

void rprof_recv(double t) {
    rp_recv_tm += t;
    rp_recv_c++;
}

void rprof_recv_tcp1(double t) {
    rp_recv_tcp1_tm += t;
    rp_recv_tcp1_c++;
}

void rprof_recv_tcp2(double t) {
    rp_recv_tcp2_tm += t;
    rp_recv_tcp2_c++;
}

void rprof_handle_secure(double t) {
    rp_handle_secure_tm += t;
    rp_handle_secure_c++;
}

void rprof_reload_keys(double t) {
    rp_reload_keys_tm += t;
    rp_reload_keys_c++;
}

void rprof_read_sec_msg(double t) {
    rp_read_sec_msg_tm += t;
    rp_read_sec_msg_c++;
}

void rprof_save_control_msg(double t) {
    rp_save_control_msg_tm += t;
    rp_save_control_msg_c++;
}

void rprof_write_file(double t) {
    rp_write_file_tm += t;
    rp_write_file_c++;
}

void rprof_msg_enqueue(double t) {
    rp_msg_enqueue_tm += t;
    rp_msg_enqueue_c++;
}

void rprof_send(double t) {
    rp_send_tm += t;
    rp_send_c++;
}
