/*
 * krb525 deamon
 *
 * $Id: server.c,v 1.11 1999/10/11 16:48:01 vwelch Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "krb5.h"
#include "com_err.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>

#include "krb525.h"
#include "server.h"
#include "auth_con.h"
#include "netio.h"
#include "srv_conf.h"
#ifdef K5_DB_CODE
#include "k5_db.h"
#endif
#include "version.h"


#define KRB525_CONF_FILE	INSTALLPATH "/etc/krb525.conf"


static void handle_connection(krb5_context,
			      int,
			      krb5_principal,
			      krb5_keytab);

static int log_request(krb5_context,
		       krb525_request *);

static krb5_error_code read_request(krb5_context,
				    krb5_auth_context,
				    int,
				    krb525_request *);

static krb5_error_code decrypt_request_ticket(krb5_context,
					      krb525_request *,
					      krb5_keytab);

static krb5_error_code encrypt_request_ticket(krb5_context,
					      krb525_request *,
					      krb5_keytab);

static int validate_request_with_db(krb5_context,
				    krb525_request *);

static int validate_request_with_kt(krb5_context,
				    krb525_request *);

static char validate_error[256];

static char *progname;

static krb5_boolean use_k5_db = 0;	/* Use krb5 data to get service keys? */
static krb5_boolean use_keytab = 0;	/* Use a keytab to get service keys? */


int
main(argc, argv)
    int argc;
    char *argv[];
{
    krb5_context context;

    int sock = -1;			/* incoming connection fd */
    short port = 0;			/* If user specifies port */

    krb5_data resp_data;

    krb5_error_code retval;

    krb5_principal my_princ;

    char *service = KRB525_SERVICE;

    extern int opterr, optind;
    extern char * optarg;
    int ch;

    krb5_keytab keytab = NULL;
    char *keytab_name = NULL;


    krb5_replay_data replay_data;

    char *conf_file = KRB525_CONF_FILE;


    /* Get our name, removing preceding path */
    if (progname = strrchr(argv[0], '/'))
	progname++;
    else
	progname = argv[0];

    /* open a log connection */
    openlog(progname, LOG_PID, LOG_DAEMON);

    retval = krb5_init_context(&context);
    if (retval) {
	    com_err(argv[0], retval, "while initializing krb5");
	    exit(1);
    }

    /*
     * Ignore SIGPIPEs that may get thrown because the client died on us.
     */
    (void) signal(SIGPIPE, SIG_IGN);

    /*
     * Parse command line arguments
     *  
     */
    opterr = 0;

    while ((ch = getopt(argc, argv, "c:dkp:t:s:V")) != EOF)
	switch (ch) {
	case 'c':
	    conf_file = optarg;
	    break;

	case 'd':
#ifdef K5_DB_CODE
	    use_k5_db = 1;
	    break;
#else
	    syslog(LOG_ERR, "K5 DB code (-d option) not supported");
	    exit(1);
#endif

	case 'k':
	    use_keytab = 1;
	    break;

	case 'p':
	    port = atoi(optarg);
	    break;

	case 's':
	    service = optarg;
	    break;

	case 't':
	    keytab_name = optarg;
	    break;

	case 'V':
	    printf("%s Version %s\n", progname, KRB525_VERSION_STRING);
	    exit(0);
       
	case '?':
	default:
	    opterr++;
	    break;
	}

    if (use_keytab && use_k5_db) {
	syslog(LOG_ERR, "%s: Cannot specify both DB (-d) and keytab (-k)\n",
	       progname);
	opterr++;
    }

    if (opterr) {
	fprintf(stderr, "%s: Argument error - see syslog", progname);
	fprintf(stderr, "Usage: %s [<options>]\n"
		" Options are:\n"
		"   -c <filename>            Specify configuration file\n"
                "                             (Default is " KRB525_CONF_FILE ")\n"
#ifdef K5_DB_CODE
		"   -d                       Use K5 Database <default>\n"
		"   -k                       Use keytab\n"
#endif
                "   -p <port>                Port to listen on\n"
                "   -s <service name>        My service name\n"
		"   -t <keytab name>         Keytab to use\n"
		"   -V                       Print version and exit\n",
		progname);
	syslog(LOG_ERR, "Exiting with argument error");
	exit(1);
    }

    argc -= optind;
    argv += optind;

    /* Use keytab or DB if not specified? */
    if (!use_keytab && !use_k5_db) {
#if K5_DB_CODE
	use_k5_db = 1;
#else
        use_keytab = 1;
#endif
    }

    /* Read my configuration file */
    if (init_conf(conf_file)) {
	syslog(LOG_ERR, "Reading configuration file: %s", srv_conf_error);
	exit(1);
    }

    if (use_keytab) {
	/* Open the keytab */
	if (keytab_name)
	    retval = krb5_kt_resolve(context, keytab_name, &keytab);
	else
	    retval = krb5_kt_default(context, &keytab);

	if (retval) {
	    com_err(progname, retval,
		    "while resolving keytab file %s",
		    (keytab_name ? keytab_name : "(default)"));
	    exit(1);
	}
    }

#ifdef K5_DB_CODE
    if (use_k5_db) {
	/* Open the K5 Database */
	retval = k5_db_init(progname, context, NULL);
	
	if (retval == -1) {
	    syslog(LOG_ERR, "%s while initializing K5 DB", k5_db_error);
	    exit(1);
	}
    }	
#endif

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

	if ((acc = accept(sock, NULL, NULL)) == -1){
	    syslog(LOG_ERR, "accept: %m");
	    exit(1);
	}
	dup2(acc, 0);
	close(sock);
	sock = 0;
    } else {
	/* Socket already on fd 0 */
	sock = 0;
    }

    handle_connection(context, sock, my_princ, keytab);

    close(sock);

done:
    free_conf();
#ifdef K5_DB_CODE
    if (use_k5_db)
	k5_db_close(context);
#endif
    krb5_free_principal(context, my_princ);
    krb5_free_context(context);

    exit(0);
}


/* For use in handle_connect() - response with a generic error */
#define RESPOND_ERROR() { snprintf(errbuf, sizeof(errbuf), "SYSTEM ERROR"); \
                          response_status = STATUS_ERROR; \
                          goto respond; }

/* For use in handle_connect() - response with permission denied */
#define RESPOND_DENIED() { snprintf(errbuf, sizeof(errbuf), \
                                    "Permission denied"); \
                           response_status = STATUS_ERROR; \
                           goto respond; }

static void
handle_connection(krb5_context context,
		  int sock,
		  krb5_principal my_princ,
		  krb5_keytab keytab)
{
    krb5_error_code retval;
    krb5_auth_context auth_context = NULL;
    krb5_ticket * recvauth_ticket = NULL; /* Ticket used to authenticate */
    krb5_data *converted_ticket = NULL;	/* Converted ticket */

    krb525_request request;		/* Information about request */

    int response_status;
    char errbuf[BUFSIZ];

    krb5_data resp_data;		/* Buffer for response */


    memset(&request, 0, sizeof(request));
    
    retval = krb5_recvauth(context, &auth_context, (krb5_pointer)&sock,
			   KRB525_VERSION, my_princ, 
			   0,	/* no flags */
			   keytab,	/* default keytab is NULL */
			   &recvauth_ticket);

    if (retval) {
	syslog(LOG_ERR, "recvauth failed--%s", error_message(retval));
	goto done;
    }

    /* Prepare to encrypt/decrypt */
    retval = setup_auth_context(context, auth_context, sock, progname);

    if (retval) {
	syslog(LOG_ERR, "setup of auth context failed--%s",
	       error_message(retval));
	goto done;
    }
 

    /* Read request from user */
    retval = read_request(context, auth_context, sock, &request);

    if (retval)
	RESPOND_ERROR();

    /* And decrypt the ticket the user sent us */
    retval = decrypt_request_ticket(context, &request, keytab);

    if (retval)
	RESPOND_ERROR();

    /* Now we can get the real client from the ticket */
    retval = krb5_copy_principal(context,
				 request.ticket->enc_part2->client,
				 &request.tkt_client);

    if (retval) {
	syslog(LOG_ERR, "copy of client principal from ticket failed: %s",
	       error_message(retval));
	RESPOND_ERROR();
    }

    /*
     * Ok, now that we have all the information, we can log and process
     * the request.
     */

    if (log_request(context, &request))
	RESPOND_ERROR();

    /*
     * Check request with krb525 configuration
     */
    if (check_conf(&request)) {
	syslog(LOG_ERR, srv_conf_error);
	RESPOND_DENIED();
    }

    /*
     * Check the request for validity
     */
#ifdef K5_DB_CODE    
    if (use_k5_db)
	retval = validate_request_with_db(context, &request);
    else
#endif /* K5_DB_CODE */
	retval = validate_request_with_kt(context, &request);

    if (retval == -1) { /* Some sort of error */
	syslog(LOG_ERR, "Error validating request: %s",
	       validate_error);
	RESPOND_ERROR();
    }

    if (retval == 0) {
	syslog(LOG_ERR, "Validation failed: %s",
	       validate_error);
	RESPOND_DENIED()
    }


    /*
     * OK, everything checked out.
     */

    /*
     * Change the ticket as requested
     */
    krb5_free_principal(context, request.ticket->enc_part2->client);
    krb5_copy_principal(context,
			request.target_client,
			&(request.ticket->enc_part2->client));

    krb5_free_principal(context, request.ticket->server);
    krb5_copy_principal(context,
			request.target_server,
			&(request.ticket->server));


    /*
     * Now encrypt the ticket with the possibly new service key
     * and encode for shipping back to the client
     */
    retval = encrypt_request_ticket(context, &request, keytab);

    if (retval)
	RESPOND_ERROR();

    retval = encode_krb5_ticket(request.ticket, &converted_ticket);

    if (retval) { 
	syslog(LOG_ERR, "Error encoding ticket: %s",
	       error_message(retval));
	RESPOND_ERROR();
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
    /* Clean up */
    if (auth_context) krb5_auth_con_free(context, auth_context);
    if (recvauth_ticket) krb5_free_ticket(context, recvauth_ticket);
    if (converted_ticket) krb5_free_data(context, converted_ticket);

    if (request.ticket) krb5_free_ticket(context, request.ticket);
    if (request.client) krb5_free_principal(context, request.client);
    if (request.tkt_client) krb5_free_principal(context, request.tkt_client);
    if (request.tkt_server) krb5_free_principal(context, request.tkt_server);
    if (request.target_client)
	krb5_free_principal(context, request.target_client);
    if (request.target_server)
	krb5_free_principal(context, request.target_server);
}


/*
 * Log the given request. Returns -1 on error, 0 otherwise.
 */
static int
log_request(krb5_context		context,
	    krb525_request		*request)
{
    krb5_error_code			retval;

    char 				*requesting_client = NULL;
    char				*tkt_client = NULL;
    char				*tkt_server = NULL;
    char				*target_client = NULL;
    char				*target_server = NULL;

    struct hostent			*hinfo;
    char				*host;


    retval = krb5_unparse_name(context, request->client, &requesting_client) ||
	krb5_unparse_name(context, request->tkt_client, &tkt_client) ||
	krb5_unparse_name(context, request->tkt_server, &tkt_server) ||
	krb5_unparse_name(context, request->target_client, &target_client) ||
	krb5_unparse_name(context, request->target_server, &target_server);

    if (retval) {
	syslog(LOG_ERR, "Error unparsing names in request for logging: %s",
	       error_message(retval));
	goto done;
    }

    hinfo = gethostbyaddr((char *) &(request->addr.sin_addr.s_addr),
			  sizeof(request->addr.sin_addr.s_addr),
			  request->addr.sin_family);

    if (!hinfo) {
	host = inet_ntoa(request->addr.sin_addr);

    } else {
	host = hinfo->h_name;
    }

    if (!host)
	host = "<unknown>";

    syslog(LOG_INFO,
	   "Connection from %s@%s: %s for %s -> %s for %s",
	   requesting_client, host,
	   tkt_client, tkt_server,
	   target_client, target_server);

 done:
    if (requesting_client) free(requesting_client);
    if (tkt_client) free(tkt_client);
    if (tkt_server) free(tkt_server);
    if (target_client) free(target_client);
    if (target_server) free(target_server);

    if (retval)	return -1;

    return 0;
}

	
/*
 * Read the request from the client and fill in the request structure
 */
static krb5_error_code
read_request(krb5_context		context,
	     krb5_auth_context		auth_context,
	     int			sock,
	     krb525_request		*request)
{
    krb5_error_code retval;
    krb5_data inbuf;			/* Buffer for reading */
    krb5_data ticket_data;		/* Ticket to be converted */

    char *target_cname = NULL;
    char *target_sname = NULL;

    int namelen;


    ticket_data.data = NULL;

    /* Read target client from client */
    retval = read_encrypt(context, auth_context, sock, &inbuf);

    if (retval) {
	syslog(LOG_ERR, "Error reading from client: %s", netio_error);
	goto done;
    }

    target_cname = inbuf.data;

    /* Read target server from client */
    retval = read_encrypt(context, auth_context, sock, &inbuf);

    if (retval) {
	syslog(LOG_ERR, "Error reading from client: %s", netio_error);
	goto done;
    }

    target_sname = inbuf.data;

    /* Get read ticket to be converted from client */
    retval = read_encrypt(context, auth_context, sock, &ticket_data);

    if (retval) {
	syslog(LOG_ERR, "Error reading from client: %s", netio_error);
	goto done;
    }

    /* Ok, we're done reading - now fill in request */
    request->krb5_context = context;
    
    /* Decode the ticket */
    retval = decode_krb5_ticket(&ticket_data, &(request->ticket));

    if (retval) {
	syslog(LOG_ERR, "Error decoding ticket: %s", error_message(retval));
	goto done;
    }

    /* 
     * request.client has already been filled in
     */

    /*
     * Copy client and server out of the ticket for convience
     */

    /*
     * request.tkt_client will have to be filled in after the ticket
     * is decrypted.
     */
    request->tkt_client = NULL;

    retval = krb5_copy_principal(context,
				 request->ticket->server,
				 &(request->tkt_server));

    if (retval) {
	syslog(LOG_ERR, "Error copy server principal from ticket: %s",
	      error_message(retval));
	goto done;
    }

    namelen = sizeof(request->addr);
    if (getpeername(0, (struct sockaddr *)&(request->addr), &namelen) < 0) {
	syslog(LOG_ERR, "Error getting address of client: %m");
	goto done;
    }

    retval = krb5_parse_name(context, target_cname, &(request->target_client));

    if (retval) {
	syslog(LOG_ERR, "Error parsing target client \"%.100s\"", target_cname);
	goto done;
    }

    retval = krb5_parse_name(context, target_sname, &(request->target_server));

    if (retval) {
	syslog(LOG_ERR, "Error parsing target server \"%.100s\"", target_sname);
	goto done;
    }

 done:
    /* Clean up */
    if (target_cname) krb5_xfree(target_cname);
    if (target_sname) krb5_xfree(target_sname);
    if (ticket_data.data) krb5_xfree(ticket_data.data);

    return retval;
}


/*
 * Decrypt the ticket in the request
 */
static krb5_error_code
decrypt_request_ticket(krb5_context		context,
		       krb525_request		*request,
		       krb5_keytab		keytab)
{
    krb5_error_code		retval;
    krb5_keyblock 		*server_key = NULL;
    char			*service_name = NULL;


    /* Unparse the service name for logging */
    retval = krb5_unparse_name(context, request->ticket->server,
			       &service_name);

    if (retval) {
	syslog(LOG_ERR, "Error unparsing service name in ticket: %s",
	       error_message(retval));
	goto done;
    }

    /*
     * Get the services keys we need
     */
#ifdef K5_DB_CODE
    if (use_k5_db) {
	/* Get keys from db */
	retval = k5_db_get_key(context,
			       request->ticket->server, 
			       &server_key,
			       request->ticket->enc_part.enctype);

	if (retval) {
	    syslog(LOG_ERR, "Error get service key for %s from db: %s",
		   service_name, k5_db_error);
	    goto done;
	}
    } else
#endif /* K5_DB_CODE */
    {
	char keytab_name[BUFSIZ];

	/* ARGH - krb5_kt_read_service_key() needs the keytab name! */
	retval = krb5_kt_get_name(context,
				  keytab,
				  keytab_name,
				  sizeof(keytab_name));

	if (retval) {
	    syslog(LOG_ERR, "Error getting keytab file name: %s",
		   error_message(retval));
	    goto done;
	}

	/* Get keys from keytab */
	retval = krb5_kt_read_service_key(context,
					  keytab_name,
					  request->ticket->server, 
					  0, /* Any VNO */
					  request->ticket->enc_part.enctype,
					  &server_key);

	if (retval) {
	    syslog(LOG_ERR, "Error geting service key for %s from keytab: %s",
		   service_name, error_message(retval));
	    goto done;
	}
    }

    /* Decrypt */
    retval = krb5_decrypt_tkt_part(context, server_key, request->ticket);

    if (retval) {
	syslog(LOG_ERR, "Error decrypting ticket: %s", error_message(retval));
	goto done;
    }

 done:
    if (service_name) krb5_xfree(service_name);
    if (server_key) krb5_free_keyblock(context, server_key);

    return retval;
}



static krb5_error_code
encrypt_request_ticket(krb5_context		context,
		       krb525_request		*request,
		       krb5_keytab		keytab)
{
    krb5_error_code		retval;
    krb5_keyblock		*target_server_key = NULL;
    char			*service_name = NULL;

    /* Unparse the service name for logging */
    retval = krb5_unparse_name(context, request->target_server,
			       &service_name);

    if (retval) {
	syslog(LOG_ERR, "Error unparsing taget service name in ticket: %s",
	       error_message(retval));
	goto done;
    }

#ifdef K5_DB_CODE
    if (use_k5_db) {
	/* Get keys from db */

	/* XXX Use same key type here? */
	retval = k5_db_get_key(context,
			       request->target_server, 
			       &target_server_key,
			       request->ticket->enc_part.enctype);

	if (retval) {
	    syslog(LOG_ERR, "Error get service key for %s from db: %s",
		   service_name, k5_db_error);
	    goto done;
	}
    } else
#endif /* K5_DB_CODE */
    {
	char keytab_name[BUFSIZ];

	/* ARGH - krb5_kt_read_service_key() needs the keytab name! */
	retval = krb5_kt_get_name(context,
				  keytab,
				  keytab_name,
				  sizeof(keytab_name));

	if (retval) {
	    syslog(LOG_ERR, "Error getting keytab file name: %s",
		   error_message(retval));
	    goto done;
	}

	/* Get keys from keytab */
	retval = krb5_kt_read_service_key(context,
					  keytab_name,
					  request->target_server, 
					  0, /* Any VNO */
					  request->ticket->enc_part.enctype,
					  &target_server_key);

	if (retval) {
	    syslog(LOG_ERR, "Error get service key for %s from keytab: %s",
		   service_name, error_message(retval));
	    goto done;
	}
    }


    retval = krb5_encrypt_tkt_part(context, target_server_key,
				   request->ticket);

    if (retval) {
	syslog(LOG_ERR, "Error encrypting ticket: %s",
	       error_message(retval));
	goto done;
    }


 done:
    if (service_name) krb5_xfree(service_name);
    if (target_server_key) krb5_free_keyblock(context, target_server_key);

    return retval;
}


#ifdef K5_DB_CODE
/*
 * Check and validate a request using K5 database.
 * 
 * Returns 1 if legal, 0 otherwise, -1 on error, setting
 * validate_error.
 *
 * Mainly taken from kdc/kdc_util.c:validate_as_request()
 */
#define isflagset(flagfield, flag) (flagfield & (flag))

static int
validate_request_with_db(krb5_context context,
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
	krb5_dbe_free_contents(context, &server);
	return 0;
    }

    if ((retval = krb5_timeofday(context, &now))) {
	sprintf(validate_error, "Getting time of day: %s",
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
     krb5_dbe_free_contents(context, &server);
     krb5_dbe_free_contents(context, &client);
     return return_code;
}

#endif /* K5_DB_CODE */

/*
 * Check and validate a request using keytab information.
 * 
 * Returns 1 if legal, 0 otherwise, -1 on error, setting
 * validate_error.
 */

static int
validate_request_with_kt(krb5_context context,
			 krb525_request *request)
{
    /*
     * Without any principal information there is nothing to check against
     */

    return 1;
}

