/*
 * client.c
 *
 * krb525 client program
 *
 * $Id: client.c,v 1.2 1997/09/15 15:37:43 vwelch Exp $
 *
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
#include <signal.h>
#include <pwd.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc();
#endif

extern int optind;
extern char *optarg;

#include "krb525.h"
#include "netio.h"
#include "auth_con.h"


#define KRB525_HOST		"computer.ncsa.uiuc.edu"	/* XXX */


#define error_exit()	exit_code = 1; goto cleanup;


static krb5_error_code get_creds_with_keytab(krb5_context,
					     krb5_principal,
					     krb5_principal,
					     char *,
					     krb5_creds *);
static krb5_error_code get_creds_with_ccache(krb5_context,
					     krb5_principal,
					     krb5_principal,
					     char *,
					     krb5_creds *);

static int get_guid(char *,
		    uid_t *,
		    gid_t *);

static krb5_error_code get_principal_from_ccache(krb5_context,
						 char *,
						 char **,
						 krb5_principal *);


/* Globals */
static char *progname;			/* This program's name */


void
main(argc, argv)
int argc;
char *argv[];
{
    struct sockaddr_in lsin, rsin;
    int sock, namelen;

    krb5_context context;
    krb5_auth_context auth_context = 0;

    krb5_data recv_data;
    krb5_data cksum_data;
    krb5_error_code retval;
    
    int resp_status;
    int exit_code = 0;

    /* Where the krb525d daemon is running */
    char *krb525_host = KRB525_HOST;
    int krb525_port = -1;

    /* Credentials for authenticating to krb525d */
    char *krb525_cname = NULL;
    char *krb525_sname = KRB525_SERVICE;
    krb5_principal krb525_cprinc, krb525_sprinc;
    krb5_creds krb525_creds;

    /* Credentials we are converting */
    char *target_cname = NULL;
    char *target_sname = NULL;
    krb5_principal target_cprinc, target_sprinc;
    krb5_data *target_realm;
    krb5_creds target_creds;

    /* Information about target user */
    char *target_user;
    uid_t uid = -1;
    gid_t gid = -1;

    /* Where we're going to put the converted credentials */
    krb5_ccache target_ccache = NULL;
    char *target_cache_name = NULL;

    /* Where our credentials are */
    char *source_cache_name = NULL;
    int use_keytab = 0;
    char *keytab_name = NULL;

    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;

    krb5_data message;

    int arg;
    int arg_error = 0;

    int verbose = 0;



    /* Process options */
    progname = argv[0];

    while ((arg = getopt(argc, argv, "c:g:h:km:p:s:t:u:v")) != EOF)
	switch (arg) {
	case 'c':
	    source_cache_name = optarg;
	    break;

	case 'g':
	    gid = atoi(optarg);
	    if (gid == 0) {
		fprintf(stderr, "Illegal gid value \"%s\"\n", optarg);
		arg_error++;
	    }
	    break;

	case 'h':
	    krb525_host = optarg;
	    break;

	case 'k':
	    use_keytab = 1;
	    break;

	case 'm':
	    krb525_cname = optarg;
	    break;

	case 'p':
	    krb525_port = atoi(optarg);
	    if (krb525_port == 0) {
		fprintf(stderr, "Illegal port value \"%s\"\n", optarg);
		arg_error++;
	    }
	    break;

	case 's':
	    krb525_sname = optarg;
	    break;

	case 't':
	    keytab_name = optarg;
	    break;

	case 'u':
	    uid = atoi(optarg);
	    if (uid == 0) {
		fprintf(stderr, "Illegal uid value \"%s\"\n", optarg);
		arg_error++;
	    }
	    break;

	case 'v':
	    verbose++;
	    break;

	default:
	    arg_error++;
	    break;
	}

    if ((argc - optind) != 2)
	arg_error++;

    if (source_cache_name && use_keytab) {
	fprintf(stderr, "%s: Can't specify both keytab (-k) and cache (-c)\n",
		progname);
	arg_error++;
    }

    if (keytab_name && !use_keytab) {
	fprintf(stderr,
		"%s: Need to specify keytab (-k) to use keytab name (-t)\n",
		progname);
	arg_error++;
    }

    if (arg_error) {
	fprintf(stderr, "%s: [<options>] <target principal> <cache name>\n"
		" Options are:\n"
		"   -c <cache name>          Specify cache name to use\n"
		"   -g <gid>                 Specify gid to own target cache\n"
		"   -h <server host>         Host where server is running\n"
		"   -k                       Use keytab\n"
		"   -m <my name>             Specify my principal name\n"
		"   -p <server port>         Port where server is running\n"
		"   -s <service name>        Service name of server\n"
		"   -t <keytab file>         Keytab file to use\n"
		"   -u <uid>                 Specify uid to own target cache\n"
		"   -v                       Verbose mode\n",
		progname);
	exit(1);
    }

    if (verbose) {
	if (use_keytab) {
	    if (keytab_name)
		printf("Using keytab file %s\n", keytab_name);
	    else
		printf("Using default keytab file\n");
	} else {
	    if (source_cache_name)
		printf("Using ccache file %s\n", source_cache_name);
	    else
		printf("Using default ccache\n");
	}
    }

    /* Kerberos initialization */
    if (verbose)
	printf("Initializing Kerberos\n");

    retval = krb5_init_context(&context);
    if (retval) {
	com_err(progname, retval, "while initializing krb5");
	error_exit();
    }

    (void) signal(SIGPIPE, SIG_IGN);
    if (!valid_cksumtype(CKSUMTYPE_CRC32)) {
	com_err(progname, KRB5_PROG_SUMTYPE_NOSUPP, "while using CRC-32");
	error_exit();
    }

    
    /* Parse target principal name */
    target_user = argv[optind++];

    if (retval = krb5_parse_name(context, target_user, &target_cprinc)) {
	com_err(progname, retval, "while parsing target name");
	error_exit();
    }

    target_realm = krb5_princ_realm(context, target_cprinc);

    if (retval = krb5_unparse_name(context, target_cprinc, &target_cname)) {
	com_err(progname, retval, "while unparsing target principal");
	error_exit();
    }

    if ((uid == -1) && get_guid(target_user, &uid, &gid)) {
	fprintf(stderr, "Could not resolve uid and gid for %s\n", target_user);
	perror("User lookup");
	error_exit();
    }

    /*
     * Parse target service name. If none was given then use krbtgt/<realm>
     */
    if (target_sname == NULL) {
	if (retval = krb5_build_principal(context,
					  &target_sprinc,
					  target_realm->length,
					  target_realm->data,
					  KRB5_TGS_NAME,
					  target_realm->data,
					  0)) {
	    com_err (progname, retval,
		     "when build target service principal \"%s/%s\"",
		     target_sname, target_realm->data);
	    error_exit();
	}
    } else {
	/* Target service specified */
	if (retval = krb5_parse_name (context, target_sname,
				      &target_sprinc)) {
	 com_err (progname, retval, "when parsing name %s", target_sname);
	 error_exit();
	}
    }
   
    if (retval = krb5_unparse_name(context, target_sprinc, &target_sname)) {
	 com_err (progname, retval, "when unparsing target service");
	 error_exit();
    }


    /* Parse target cache name */
    target_cache_name = argv[optind++];

    if (retval = krb5_cc_resolve(context, target_cache_name, &target_ccache)) {
	com_err(progname, retval, "resolving target cache %s",
		target_cache_name);
	error_exit();
    }

    /*
     * Parse krb525 client name. If no client name was provided then get
     * it from the credentials cache.
     */
    if (krb525_cname == NULL) {
	if (retval = get_principal_from_ccache(context,
					       source_cache_name,
					       &krb525_cname,
					       &krb525_cprinc)) {
	    com_err (progname, retval, "- Can't get my principal name");
	    error_exit();
	}
    
    } else {
	if (retval = krb5_parse_name (context, krb525_cname, &krb525_cprinc)) {
	    com_err (progname, retval, "when parsing name %s", krb525_cname);
	    error_exit();
	}

	if (retval = krb5_unparse_name(context, krb525_cprinc, &krb525_cname)) {
	    com_err (progname, retval, "when unparsing krb525 client principal");
	    error_exit();
	}
    }

    if (verbose)
	printf("My principal name is %s\n", krb525_cname);

    /* Parse krb525 server name */
    if (retval = krb5_sname_to_principal(context, krb525_host, krb525_sname,
					 KRB5_NT_SRV_HST, &krb525_sprinc)) {
	com_err(progname, retval, "while creating server name for %s/%s",
		krb525_sname, krb525_host);
	error_exit();
    }

    if (retval = krb5_unparse_name(context, krb525_sprinc, &krb525_sname)) {
	com_err (progname, retval, "when unparsing krb525 service principal");
	error_exit();
    }
 
    /* Get credentials to converted */
    if (verbose)
	printf("Getting credentials to convert (%s for %s)\n",
	       krb525_cname, target_sname);

    if (use_keytab)
	retval = get_creds_with_keytab(context, krb525_cprinc, target_sprinc,
				       keytab_name, &target_creds);
    else
	retval = get_creds_with_ccache(context, krb525_cprinc, target_sprinc,
				       source_cache_name, &target_creds);

    if (retval) {
	com_err (progname, retval, "when getting initial ticket (%s for %s)",
		 krb525_cname, target_sname);
	error_exit();
    }


    /* Figure out the port number of the server */
    if (krb525_port == -1) {
	struct servent *sp;
	sp = getservbyname(krb525_sname, "tcp");
	if (sp) {
	    krb525_port = sp->s_port;
	} else {
	    krb525_port = KRB525_PORT;
	}
    }

    /* Connect to the server */
    if (verbose)
	printf("Connecting to krb525d (%s port %d)\n",
	       krb525_host, krb525_port);

    if ((sock = connect_to_server(krb525_host, krb525_port)) < 0) {
	perror(netio_error);
	error_exit();
    }

    /* Get addresses of connection ends */
    namelen = sizeof(rsin);
    if (getpeername(sock, (struct sockaddr *) &rsin, &namelen) < 0) {
	perror("getpeername");
	close(sock);
	error_exit();
    }

    namelen = sizeof(lsin);
    if (getsockname(sock, (struct sockaddr *) &lsin, &namelen) < 0) {
	perror("getsockname");
	close(sock);
	error_exit();
    }

    /* Get our credentials for the gateway */
    if (verbose)
	printf("Getting credentials for krb525d (%s for %s) \n",
	       krb525_cname, krb525_sname);

    if (use_keytab)
	retval = get_creds_with_keytab(context, krb525_cprinc, krb525_sprinc,
				       keytab_name, &krb525_creds);
    else
	retval = get_creds_with_ccache(context, krb525_cprinc, krb525_sprinc,
				       source_cache_name, &krb525_creds);

    if (retval) {
	com_err (progname, retval, "when getting credentials (%s for %s/%s)",
		 krb525_cname, krb525_sname, krb525_host);
	error_exit();
    }
    
    /* Authenticate to server */
    if (verbose)
	printf("Authenticating to %s\n", krb525_host);

    /*
     * I have no idea what the cksum_data stuff is for or why it uses
     * the hostname of the server.
     */
    cksum_data.data = krb525_host;
    cksum_data.length = strlen(krb525_host);

    retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &sock,
			   KRB525_VERSION,
			   krb525_cprinc,	/* Not needed */
			   krb525_sprinc,	/* Not needed */
			   AP_OPTS_MUTUAL_REQUIRED,
			   &cksum_data,
			   &krb525_creds,
			   NULL, &err_ret, &rep_ret, NULL);

    if (retval && retval != KRB5_SENDAUTH_REJECTED) {
	com_err(progname, retval, "while using sendauth");
	error_exit();
    }
    if (retval == KRB5_SENDAUTH_REJECTED) {
	/* got an error */
	printf("sendauth rejected, error reply is:\n\t\"%*s\"\n",
	       err_ret->text.length, err_ret->text.data);
	error_exit();
    }

    if (rep_ret == NULL) {
	com_err(progname, 0, "no error or reply from sendauth!");
	error_exit();
    }

    if (verbose)
	printf("sendauth succeeded\n");

    /* Prepare to encrypt */
    if (retval = setup_auth_context(context, auth_context, &lsin, &rsin,
				     krb525_cname)) {
	com_err(progname, retval, auth_con_error);
	error_exit();
    }

    /* Send target client name */
    message.data = target_cname;
    message.length = strlen(target_cname) + 1;

    if (retval = send_encrypt(context, auth_context, sock, message)) {
	fprintf(stderr, "%s\n", netio_error);
	error_exit();
    }
 
    /* Set my ticket to be massaged */
    message.data = target_creds.ticket.data;
    message.length = target_creds.ticket.length;

    if (retval = send_encrypt(context, auth_context, sock, message)) {
	fprintf(stderr, "%s\n", netio_error);
	error_exit();
    }
 
    /* Read reply */
    if ((retval = read_msg(context, sock, &recv_data)) < 0) {
	fprintf(stderr, "%s\n", netio_error);
	error_exit();
    }
    
    resp_status = *((int *) recv_data.data);

    switch(resp_status) {
    case STATUS_OK:
	/* Read new ticket from server */
	if ((retval = read_encrypt(context, auth_context, sock, &recv_data))
	    < 0) {
	    fprintf(stderr, "%s\n", netio_error);
	    error_exit();
	}

	if (verbose)
	    printf("New ticket read from server\n");

	/* Put new ticket data into credentials */
	target_creds.ticket.data = recv_data.data;
	target_creds.ticket.length = recv_data.length;

	/* Massage other fields of credentials */
	target_creds.client = target_cprinc;

	/* Ok now store the ticket */
	if (retval = krb5_cc_initialize(context, target_ccache, target_cprinc)) {
	    com_err(progname, retval, "initializing cache");
	    error_exit();
	}

	if (retval = krb5_cc_store_cred(context, target_ccache, &target_creds)) {
	    com_err(progname, retval, "storing credentials");
	    error_exit();
	}

	if (chown(target_cache_name, uid, gid)) {
	    perror("Setting owner of credentials cache");
	    error_exit();
	}
	    

	if (verbose)
	    printf("Credentials stored in %s\n", target_cache_name);

	break;

    case STATUS_ERROR:	
	/* Read and print error message from server */
	if ((retval = read_encrypt(context, auth_context, sock, &recv_data))
	    < 0) {
	    fprintf(stderr, "%s\n", netio_error);
	    error_exit();
	}

        printf(recv_data.data);
	break;

    default:
	printf("Unknown response status %d\n", resp_status);
    }

cleanup:
    /* XXX - lots of cleanup should be done here */
    close(sock);
    exit(resp_status);
}



/*
 * Fill in the structure pointed to by creds with credentials with
 * credentials for client/server using the keytab file indicated by the
 * path pointed to by keytab_name.
 */
static krb5_error_code
get_creds_with_keytab(krb5_context context,
		      krb5_principal client,
		      krb5_principal server,
		      char *keytab_name,
		      krb5_creds *creds)
{
    krb5_error_code	retval;
    krb5_flags		options = 0;
    krb5_address 	**addrs = (krb5_address **)0;
    krb5_preauthtype 	*preauth = NULL;
    krb5_preauthtype 	preauth_list[2] = { 0, -1 };
    krb5_keytab		keytab;

    if (keytab_name) {
	if (retval = krb5_kt_resolve(context, keytab_name, &keytab)) {
	    com_err(progname, retval, "while parsing keytab \"%s\"",
		    keytab_name);
	    return retval;
	}
    } else {
	if (retval = krb5_kt_default(context, &keytab)) {
	    com_err(progname, retval, "while getting default keytab");
	    return retval;
	}
    }   

    memset((char *)creds, 0, sizeof(*creds));

    creds->client = client;
    creds->server = server;

    if (retval = krb5_get_in_tkt_with_keytab(context, options, addrs,
					     NULL, preauth, keytab, 0,
					     creds, 0)) {
	com_err(progname, retval, "when getting credentials");
	return retval;
    }

    return retval;
}

/*
 * Fill in the structure pointed to by creds with credentials with
 * credentials for client/server using the keytab file indicated by the
 * path pointed to by keytab_name.
 */
static krb5_error_code
get_creds_with_ccache(krb5_context context,
		      krb5_principal client,
		      krb5_principal server,
		      char *cache_name,
		      krb5_creds *creds)
{
    krb5_error_code	retval;
    krb5_address 	**addrs = (krb5_address **)0;
    krb5_preauthtype 	*preauth = NULL;
    krb5_preauthtype 	preauth_list[2] = { 0, -1 };
    krb5_ccache		ccache;
    krb5_flags		options = 0;
    krb5_creds		in_creds, *out_creds;


    if (!cache_name)
	retval = krb5_cc_default(context, &ccache);
    else
	retval = krb5_cc_resolve(context, cache_name, &ccache);

    if (retval) {
	com_err(progname, retval, "resolving cache name %s",
		(cache_name ? cache_name : "(default)"));
	return retval;
    }

    memset((char *)&in_creds, 0, sizeof(in_creds));

    in_creds.client = client;
    in_creds.server = server;

    if (retval = krb5_get_credentials(context, options, ccache,
				      &in_creds, &out_creds)) {
	com_err(progname, retval, "when getting credentials");
	return retval;
    }

    memcpy((char *) creds, (char *) out_creds, sizeof(*creds));

    krb5_xfree(out_creds);

    return retval;
}


/*
 * Fill in the user's gid and uid in the supplied integers.
 *
 * Returns -1 if the user could not be found, 0 otherwise.
 */
static int
get_guid(char *username,
	 uid_t *uid,
	 gid_t *gid)
{
    struct passwd *passwdent;


    passwdent = getpwnam(username);

    if (passwdent == NULL)
	return -1;

    *uid = passwdent->pw_uid;
    *gid = passwdent->pw_gid;

    return 0;
}



/*
 * Get the default principal from a cache.
 */
static krb5_error_code
get_principal_from_ccache(krb5_context context,
			  char *cache_name,
			  char **princ_name,
			  krb5_principal *princ)
{
    krb5_ccache		ccache;
    krb5_error_code	retval;


    if (!cache_name)
	retval = krb5_cc_default(context, &ccache);
    else
	retval = krb5_cc_resolve(context, cache_name, &ccache);

    if (retval) {
	com_err(progname, retval, "resolving cache name %s",
		(cache_name ? cache_name : "(default)"));
	return retval;
    }

    if (retval = krb5_cc_get_principal(context, ccache, princ)) {
	com_err(progname, retval, "in krb5_cc_get_principal()");
	return retval;
    }

    if (retval = krb5_unparse_name(context, *princ, princ_name))
	 com_err (progname, retval, "in krb5_unparse_name()");

    return retval;
}


