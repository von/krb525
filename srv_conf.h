/*
 * srv_conf.h
 *
 * $Id: srv_conf.h,v 1.3 1999/10/08 19:49:26 vwelch Exp $
 */

#ifndef __SRV_CONF_H
#define __SRV_CONF_H

#include <sys/types.h>
#include <sys/socket.h>

#include "server.h"

extern int init_conf(char *);
extern void free_conf();
extern int check_conf(krb525_request *);

extern char srv_conf_error[];

#endif /* __SRV_CONF_H */
