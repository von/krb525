/*
 * srv_conf.h
 *
 * $Id: srv_conf.h,v 1.1 1997/09/08 15:41:33 vwelch Exp $
 */

#ifndef __SRV_CONF_H
#define __SRV_CONF_H

#include <sys/types.h>
#include <sys/socket.h>

extern int check_conf(char *,
		      char *,
		      char *,
		      char *);

extern char srv_conf_error[];

#endif /* __SRV_CONF_H */
