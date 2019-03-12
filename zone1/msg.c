/* Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved */

#include <msg.h>
#include <string.h>
#include <libhexfive.h>

void msg_init(msg_t *msg, int zone){
    msg->zone = zone;
}

int msg_read(msg_t *msg, char *buf, size_t len){
    char data[16];
    int i = 0;

    ECALL_YIELD();
    if (ECALL_RECV(msg->zone, data)) {
        buf[0] = data[0];
        i = 1;
    }

    return i;
}

int msg_write(msg_t *msg, char *buf, size_t len){
    int i = 0;
    char data[16];

    while (i < len) {
        int transfer = len - i;
        if (transfer > 16)
            transfer = 16;

        memset(data, 0, 16);
        memcpy(data, buf, transfer);

        if (ECALL_SEND(msg->zone, data)) {
            i += transfer;
            buf += transfer;
        }
        ECALL_YIELD();
    }

    if (len % 16 == 0) {
        memset(data, 0, 16);
        while (!ECALL_SEND(msg->zone, data)) {
            ECALL_YIELD();
        }
    }

    return i;
}
