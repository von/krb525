/*
 * krb525 deamon
 *
 * $Id: server.c,v 1.2 1997/09/15 15:37:45 vwelch Exp $
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
#include "auth_con.h"
#include "netio.h"
#include "srv_conf.h"
#include "k5_db.h"


#define KRB525_CONF_FILE	INSTALLPATH "/etc/krb525.conf"


#define MY_NAME	"krb525d"


void
main(argc, argv)
    int argc;
    char *argv[];
{
    krb5_context context;
    krb5_auth_context auth_context = NULL;

    krb5_ticket * ticket;

    struct sockaddr_in rsin, lsin;
    int namelen = sizeof(rsin);
    int sock = -1;			/* incoming connection fd */
    short port = 0;			/* If user specifies port */

    krb5_data resp_data;

    krb5_error_code retval;

    krb5_principal my_princ, target_princ;

    char errbuf[BUFSIZ];
    char *target_cname, *cname, *sname;
    char *service = KRB525_SERVICE;

    extern int opterr, optind;
    extern char * optarg;
    int ch;

    krb5_keytab keytab = NULL;	/* Allow specification on command line */
    char *progname;

    int response_status;

    krb5_data inbuf;
    krb5_replay_data replay_data;

    char *conf_file = KRB525_CONF_FILE;

    krb5_data ticket_data, *converted_ticket;
    krb5_ticket *client_tkt;
    krb5_keyblock server_key;


    progname = MY_NAME;

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
			       &ticket)) {
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

    target_cname = inbuf.data;

    /* Get client ticket */
    if ((retval = read_encrypt(context, auth_context, sock, &ticket_data)) < 0) {
	syslog(LOG_ERR, "Error reading from client: %s", netio_error);
	exit(1);
    }

    /* Get client name */
    if (retval = krb5_unparse_name(context, ticket->enc_part2->client, &cname)){
	syslog(LOG_ERR, "unparse failed from %s port %d: %s",
	       inet_ntoa(rsin.sin_addr),
	       rsin.sin_port,
	       error_message(retval));
        sprintf(errbuf, "System error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    syslog(LOG_INFO, "Connection: %s from %s",
	   cname,
	   inet_ntoa(rsin.sin_addr));

    /* Parse target name */
    if (retval = krb5_parse_name(context, target_cname, &target_princ)) {
	syslog(LOG_ERR, "parse of target name \"%s\" failed: %s",
	       target_cname,
	       error_message(retval));
        sprintf(errbuf, "System error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    /* Check client with configuration */
    if (check_conf(conf_file,
		   cname,
		   target_cname,
		   (char *) inet_ntoa(rsin.sin_addr)) != 0) {
	sprintf(errbuf, "Permission denied\n");
	syslog(LOG_ERR, srv_conf_error);
	response_status = STATUS_ERROR;
	goto respond;
    }

    /* Decode the ticket */
    retval = decode_krb5_ticket(&ticket_data, &client_tkt);

    if (retval) {
	syslog(LOG_ERR, "Error decoding ticket: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    if (retval = krb5_unparse_name(context, client_tkt->server, &sname)) {
	syslog(LOG_ERR, "Error unparsing ticket server: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    syslog(LOG_INFO, "target ticket is %s for %s", target_cname, sname);

    /*
     * BIG XXX - Need to add checks to make sure target is valid (hasn't
     * expired, password hasn't expired, etc.
     *           
     */
    
    /* Get the service key and decrypt */
    if (retval = k5_db_get_key(context,
			       client_tkt->server, 
			       &server_key,
			       client_tkt->enc_part.enctype)) {
	syslog(LOG_ERR, "Error get service key for %s: %s",
	       sname, k5_db_error);
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    if (retval = krb5_decrypt_tkt_part(context, &server_key, client_tkt)) {
	syslog(LOG_ERR, "Error decrypting ticket: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    /* OK, change the client name in the ticket and reencrypt */
    client_tkt->enc_part2->client = target_princ;


    if (retval = krb5_encrypt_tkt_part(context, &server_key, client_tkt)) {
	syslog(LOG_ERR, "Error encrypting ticket: %s",
	       error_message(retval));
	sprintf(errbuf, "Server error\n");
	response_status = STATUS_ERROR;
	goto respond;
    }

    if (retval = encode_krb5_ticket(client_tkt, &converted_ticket)) {
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
    k5_db_close(context);
    krb5_auth_con_free(context, auth_context);
    krb5_free_context(context);
    krb5_xfree(target_cname);
    free(cname);
    exit(0);
}
