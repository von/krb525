/*
 * krb525d include file
 *
 * $Id: server.h,v 1.1 1997/09/17 16:58:03 vwelch Exp $
 */

#ifndef __SERVER_H
#define __SERVER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "krb5.h"

/*
 * The request we're handling.
 */
typedef struct {
    /* Our Kerberos context */
    krb5_context	krb5_context;
    /* Ticket we're converting */
    krb5_ticket		*ticket;
    /* Requesting client */
    char		*cname;
    /* Original service */
    char		*sname;
    /* Client's host */
    struct sockaddr_in	addr;
    /* Target Client */
    char		*target_cname;
    krb5_principal	target_client;
    /* Target server */
    char		*target_sname;
    krb5_principal	target_server;
} krb525_request;


#endif /* __SERVER_H */
