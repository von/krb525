/*
 * srv_conf.h
 *
 * $Id: srv_conf.h,v 1.2 1997/09/17 16:58:06 vwelch Exp $
 */

#ifndef __SRV_CONF_H
#define __SRV_CONF_H

#include <sys/types.h>
#include <sys/socket.h>

#include "server.h"

extern int init_conf(char *);
extern void free_conf();
extern int check_conf(krb525_request *,
		      krb5_ticket *);

extern char srv_conf_error[];

#endif /* __SRV_CONF_H */
