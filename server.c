/*
 * krb525 deamon
 *
 * $Id: server.c,v 1.4 1997/09/17 20:43:24 vwelch Exp $
 */

#include "krb5.h"
#include "com_err.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>

#include "krb525.h"
#include "server.h"
#include "auth_con.h"
#include "netio.h"
#include "srv_conf.h"
#include "k5_db.h"


#define KRB525_CONF_FILE	INSTALLPATH "/etc/krb525.conf"


#define MY_NAME	"krb525d"

static int validate_request(krb5_context,
			    krb525_request *);
static char validate_error[256];


void
main(argc, argv)
    int argc;
    char *argv[];
{
    krb5_context context;
    krb5_auth_context auth_context = NULL;

    krb5_ticket * recvauth_ticket;

    struct sockaddr_in rsin, lsin;
    int namelen = sizeof(rsin);
    int sock = -1;			/* incoming connection fd */
    short port = 0;			/* If user specifies port */

    krb5_data resp_data;

    krb5_error_code retval;

    krb5_principal my_princ;

    char errbuf[BUFSIZ];

    krb525_request request;

    char *service = KRB525_SERVICE;

    extern int opterr, optind;
    extern char * optarg;
    int ch;

    char *progname = MY_NAME;

    krb5_keytab keytab = NULL;	/* Allow specification on command line */

    int response_status;

    krb5_data inbuf;
    krb5_replay_data replay_data;

    char *conf_file = KRB525_CONF_FILE;

    krb5_data ticket_data, *converted_ticket;

    krb5_keyblock server_key, target_server_key;




    retval = krb5_init_context(&context);
    if (retval) {
	    com_err(argv[0], retval, "while initializing krb5");
	    exit(1);
    }

    /* open a log connection */
    openlog(MY_NAME, LOG_PID, LOG_DAEMON);

    /*
     * Parse command line arguments
     *  
     */
    opterr = 0;

    while ((ch = getopt(argc, argv, "p:t:s:")) != EOF)
    switch (ch) {
    case 'p':
	port = atoi(optarg);
	break;

    case 's':
	service = optarg;
	break;

    case 't':
	if (retval = krb5_kt_resolve(context, optarg, &keytab)) {
	    com_err(progname, retval,
		    "while resolving keytab file %s", optarg);
	    exit(2);
	}
	break;

    case '?':
    default:
	opterr++;
	break;
    }

    if (opterr) {
	/* XXX Insert usage here */
	fprintf(stderr, "Argument Error\n");
	exit(1);
    }

    argc -= optind;
    argv += optind;


    /* Read my configuration file */
    if (init_conf(conf_file)) {
	syslog(LOG_ERR, "Reading configuration file: %s", srv_conf_error);
	exit(1);
    }

    /* Open the K5 Database */
    if ((retval = k5_db_init(progname, context, NULL)) == -1) {
	syslog(LOG_ERR, "%s while initializing K5 DB", k5_db_error);
	exit(1);
    }

    /* Get our service principal */
    if (retval = krb5_sname_to_principal(context, NULL, service, 
					 KRB5_NT_SRV_HST, &my_princ)) {
	syslog(LOG_ERR, "while generating service name (%s): %s",
	       service, error_message(retval));
	exit(1);
    }
    
    /*
     * If user specified a port, then listen on that port; otherwise,
     * assume we've been started out of inetd. 
     */

    if (port) {
	int acc;

	sock = make_accepting_sock(port);

	if (sock == -1) {
	    syslog(LOG_ERR, netio_error);
	    exit(1);
	}

	if ((acc = accept(sock, (struct sockaddr *)&rsin, &namelen)) == -1){
	    syslog(LOG_ERR, "accept: %m");
	    exit(1);
	}
	dup2(acc, 0);
	close(sock);
	sock = 0;
    } else {
	/*
	 * To verify authenticity, we need to know the address of the
	 * client.
	 */
	if (getpeername(0, (struct sockaddr *)&rsin, &namelen) < 0) {
	    syslog(LOG_ERR, "getpeername: %m");
	    exit(1);
	}
	sock = 0;
    }


    namelen = sizeof(lsin);
    if (getsockname(sock, (struct sockaddr *) &lsin, &namelen) < 0) {
	perror("getsockname");
	close(sock);
	exit(1);
    }

    if (retval = krb5_recvauth(context, &auth_context, (krb5_pointer)&sock,
			       KRB525_VERSION, my_princ, 
			       0,	/* no flags */
			       keytab,	/* default keytab is NULL */
			       &recvauth_ticket)) {
	syslog(LOG_ERR, "recvauth failed--%s", error_message(retval));
	exit(1);
    }

    /* Prepare to encrypt/decrypt */
    if (retval = setup_auth_context(context, auth_context, &lsin, &rsin,
				    service)) {
	com_err(progname, retval, auth_con_error);
	exit(1);
    }
 
    /* Get target client */
    if ((retval = read_encrypt(context, auth_context, sock, &inbuf)) < 0) {
	syslog(LOG_ERR, "Error reading from client: %s", netio_error);
	exit(1);
    }

    request.target_cname = inbuf.data;

    /* Get target server */
    if ((retval = read_encrypt(context, auth_context, sock, &inbuf)) < 0) {
	syslog(LOG_ERR, "Error reading from client: %s", netio_error);
	exit(1);
    }

    request.target_sname = inbuf.data;

    /* Get client ticket */
    if ((retval = read_encrypt(context, auth_context, sock, &ticket_data)) < 0) {
	syslog(LOG_ERR, "Error reading from client: %s", netio_error);
	exit(1);
    }

    /* Get client name */
    if (retval = krb5_unparse_name(context,
				   recvauth_ticket->enc_part2->client,
				   &request.cname)){
	syslog(LOG_ERR, "unparse failed from %s port %d: %s",
	       inet_ntoa(rsin.sin_addr),
	       rsin.sin_port,
	       error_message(retval));
        sprintf(errbuf, "System error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    syslog(LOG_INFO, "Connection: %s from %s",
	   request.cname,
	   inet_ntoa(rsin.sin_addr));

    /* Parse target principal names */
    if (retval = krb5_parse_name(context,
				 request.target_cname,
				 &request.target_client)) {
	syslog(LOG_ERR, "parse of target client \"%s\" failed: %s",
	       request.target_cname,
	       error_message(retval));
        sprintf(errbuf, "Permission denied\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    if (retval = krb5_parse_name(context,
				 request.target_sname,
				 &request.target_server)) {
	syslog(LOG_ERR, "parse of target server \"%s\" failed: %s",
	       request.target_sname,
	       error_message(retval));
        sprintf(errbuf, "Permission denied\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    /* Decode the ticket */
    retval = decode_krb5_ticket(&ticket_data, &request.ticket);

    if (retval) {
	syslog(LOG_ERR, "Error decoding ticket: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    if (retval = krb5_unparse_name(context,
				   request.ticket->server,
				   &request.sname)) {
	syslog(LOG_ERR, "Error unparsing ticket server: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    syslog(LOG_INFO, "converting ticket: %s for %s to %s for %s",
	   request.cname, request.sname,
	   request.target_cname, request.target_sname);

    /*
     * Fill in rest of fields in request
     */
    request.krb5_context = context;
    memcpy(&request.addr, &rsin, sizeof(request.addr));

    /*
     * Get the services keys we need
     */

    if (retval = k5_db_get_key(context,
			       request.ticket->server, 
			       &server_key,
			       request.ticket->enc_part.enctype)) {
	syslog(LOG_ERR, "Error get service key for %s: %s",
	       request.sname, k5_db_error);
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    /* XXX Use same key type here? */
    if (retval = k5_db_get_key(context,
			       request.target_server, 
			       &target_server_key,
			       request.ticket->enc_part.enctype)) {
	syslog(LOG_ERR, "Error get service key for %s: %s",
	       request.target_sname, k5_db_error);
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    
    /* Decrypt */
    if (retval = krb5_decrypt_tkt_part(context, &server_key, request.ticket)) {
	syslog(LOG_ERR, "Error decrypting ticket: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    /*
     * Ok, now that we have all the information, check everything out
     */

    /*
     * Check request with krb525 configuration
     */
    if (check_conf(&request, request.ticket)) {
	sprintf(errbuf, "Permission denied\n");
	syslog(LOG_ERR, srv_conf_error);
	response_status = STATUS_ERROR;
	goto respond;
    }

    /*
     * Check the request for validity
     */
    if (retval = validate_request(context, &request) != 1) {
	if (retval == -1) { /* Some sort of error */
	    syslog(LOG_ERR, "Error validating request: %s",
		   validate_error);
	    sprintf(errbuf, "Server error\n");
	    response_status = STATUS_ERROR;
	    goto respond;
	}

	syslog(LOG_ERR, "Validation failed: %s",
	       validate_error);
	sprintf(errbuf, "Permission denied\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    /*
     * OK, everything checked out. So, we change the client in the ticket,
     * then re-encode it.
     */
    request.ticket->enc_part2->client = request.target_client;


    if (retval = krb5_encrypt_tkt_part(context, &target_server_key,
				       request.ticket)) {
	syslog(LOG_ERR, "Error encrypting ticket: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    /* XXX - free keys here */

    if (retval = encode_krb5_ticket(request.ticket, &converted_ticket)) {
	syslog(LOG_ERR, "Error encoding ticket: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }
 
    response_status = STATUS_OK;

respond:
    /* Write response */
    resp_data.length = sizeof(response_status);
    resp_data.data = (char *) &response_status;

    if ((retval = send_msg(context, sock, resp_data)) < 0) {
	syslog(LOG_ERR, "Sending response status to client: %s", netio_error);
	goto done;
    }

    switch(response_status) {
    case STATUS_OK:
	/* Send back ticket to client */
	resp_data.length = converted_ticket->length;
	resp_data.data = converted_ticket->data;
	/* XXX Free converted ticket */
	break;
	
    case STATUS_ERROR:
	/* Return error string */
	resp_data.length = strlen(errbuf) + 1;
	resp_data.data = errbuf;
	break;

    default:
	syslog(LOG_ERR, "Programing error: response_status is %d",
	       response_status);
	goto done;
    }

    retval = send_encrypt(context, auth_context, sock, resp_data);
    if (retval < 0) {
	syslog(LOG_ERR, "Error sending response to client: %s", netio_error);
    }

done:
    free_conf();
    k5_db_close(context);
    krb5_auth_con_free(context, auth_context);
    krb5_free_context(context);
    krb5_xfree(request.target_cname);
    free(request.cname);
    /* XXX sure I'm missings some free()s here */
    exit(0);
}



/*
 * Check and validate a request against kerberos configuration.
 * 
 * Returns 1 if legal, 0 otherwise, -1 on error, setting
 * validate_error.
 *
 * Mainly taken from kdc/kdc_util.c:validate_as_request()
 */
#define isflagset(flagfield, flag) (flagfield & (flag))

static int
validate_request(krb5_context context,
		 krb525_request *request)
{
    krb5_db_entry client;
    krb5_db_entry server;
    krb5_timestamp now;
    krb5_error_code retval;
    int return_code = 0;
    

    if (k5_db_get_entry(context, request->target_server, &server)) {
	sprintf(validate_error, "Getting server DB entry: ");
	strcat(validate_error, k5_db_error);
	return 0;
    }
    
    if (k5_db_get_entry(context, request->target_client, &client)) {
	sprintf(validate_error, "Getting server DB entry: ");
	strcat(validate_error, k5_db_error);
	/* XXX Free server entry? */
	return 0;
    }

    if ((retval = krb5_timeofday(context, &now))) {
	sprintf(validate_error, "Getting time of data: %s",
		error_message(retval));
	return_code = -1;
	goto done;
    }

    /* The client's password must not be expired, unless the server is
      a KRB5_KDC_PWCHANGE_SERVICE. */
    if (client.pw_expiration && client.pw_expiration < now &&
	!isflagset(server.attributes, KRB5_KDB_PWCHANGE_SERVICE)) {
	sprintf(validate_error, "Client password expired");
	goto done;
    }

    /* The client must not be expired */
    if (client.expiration && client.expiration < now) {
	sprintf(validate_error, "Client expired");
	goto done;
    }

    /* The server must not be expired */
    if (server.expiration && server.expiration < now) {
	sprintf(validate_error, "Server expired");
	goto done;
    }

    /*
     * If the client requires password changing, then only allow the 
     * pwchange service.
     */
    if (isflagset(client.attributes, KRB5_KDB_REQUIRES_PWCHANGE) &&
	!isflagset(server.attributes, KRB5_KDB_PWCHANGE_SERVICE)) {
	sprintf(validate_error, "Client requires password change");
	goto done;
    }

    /*
     * If ticket is postdated or postdatable then client and server
     * must allow this.
     */
    if (isflagset(request->ticket->enc_part2->flags, TKT_FLG_MAY_POSTDATE) ||
	isflagset(request->ticket->enc_part2->flags, TKT_FLG_POSTDATED)) {
	if (isflagset(client.attributes, KRB5_KDB_DISALLOW_POSTDATED)) {
	    sprintf(validate_error, "Client may not postdate");
	    goto done;
	}

	if (isflagset(server.attributes, KRB5_KDB_DISALLOW_POSTDATED)) {
	    sprintf(validate_error, "Server may not postdate");
	    goto done;
	}
    }

    /* 
     * If ticket is forwardable then client and server must allow this.
     */
    if (isflagset(request->ticket->enc_part2->flags, TKT_FLG_FORWARDABLE)) {
	if (isflagset(client.attributes, KRB5_KDB_DISALLOW_FORWARDABLE)) {
	    sprintf(validate_error, "Client may not forward");
	    goto done;
	}

	if (isflagset(server.attributes, KRB5_KDB_DISALLOW_FORWARDABLE)) {
	    sprintf(validate_error, "Server may not forward");
	    goto done;
	}
    }


    /*
     * If ticket is renewable then client and server must allow this.
     */
    if (isflagset(request->ticket->enc_part2->flags, TKT_FLG_RENEWABLE)) {
	if (isflagset(client.attributes, KRB5_KDB_DISALLOW_RENEWABLE)) {
	    sprintf(validate_error, "Client may not renew");
	    goto done;
	}

	if (isflagset(server.attributes, KRB5_KDB_DISALLOW_RENEWABLE)) {
	    sprintf(validate_error, "Server may not renew");
	    goto done;
	}
    }

    /*
     * If ticket is proxiable then client and server must allow this.
     */
    if (isflagset(request->ticket->enc_part2->flags, TKT_FLG_PROXIABLE)) {
	if (isflagset(client.attributes, KRB5_KDB_DISALLOW_PROXIABLE)) {
	    sprintf(validate_error, "Client may not proxy");
	    goto done;
	}

	if (isflagset(server.attributes, KRB5_KDB_DISALLOW_PROXIABLE)) {
	    sprintf(validate_error, "Server may not proxy");
	    goto done;
	}
    }

    /* Check to see if client is locked out */
     if (isflagset(client.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
	 sprintf(validate_error, "Client is locked out");
	 goto done;
     }

    /* Check to see if server is locked out */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
	sprintf(validate_error, "Server is locked out");
	goto done;
    }

    /* Check to see if server is allowed to be a service */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_SVR)) {
	sprintf(validate_error, "Service not allowed");
	goto done;
    }

     /* Legal */
     return_code = 1;

done:
    /* XXX - Need to free entries? */
    return return_code;
}

