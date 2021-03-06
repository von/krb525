/*
 * krb525d include file
 *
 * $Id: server.h,v 1.2 1999/10/08 19:49:25 vwelch Exp $
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
    /* Ticket we're converting - may be NULL if we are just testing */
    krb5_ticket		*ticket;
    /* Requesting client */
    krb5_principal	client;
    /* Client and server from tkt */
    krb5_principal	tkt_client;
    krb5_principal	tkt_server;
    /* Client's host */
    struct sockaddr_in	addr;
    /* Target Client */
    krb5_principal	target_client;
    /* Target server */
    krb5_principal	target_server;

} krb525_request;


#endif /* __SERVER_H */
