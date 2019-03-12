/* Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved */

#ifndef MSG_H
#define MSG_H

#include <stddef.h>

typedef struct {
    int zone;
} msg_t;

void msg_init(msg_t *msg, int zone);
int msg_read(msg_t *msg, char *buf, size_t len);
int msg_write(msg_t *msg, char *buf, size_t len);

#endif /* MSG_H */
