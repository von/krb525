/*
 * client.c
 *
 * krb525 client program
 *
 * $Id: client.c,v 1.12 1999/10/11 15:50:12 vwelch Exp $
 *
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
#include <netdb.h>
#include <signal.h>
#include <pwd.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc();
#endif

#ifdef AFS_KRB5
#include <sys/stat.h>
#endif

extern int optind;
extern char *optarg;

#include "krb525.h"
#include "netio.h"
#include "auth_con.h"
#include "version.h"


#define error_exit()	{ exit_code = 1; goto cleanup; }


static krb5_error_code get_creds_with_keytab(krb5_context,
					     krb5_principal,
					     krb5_principal,
					     krb5_flags,
					     char *,
					     krb5_creds *);
static krb5_error_code get_creds_with_ccache(krb5_context,
					     krb5_principal,
					     krb5_principal,
					     krb5_flags,
					     char *,
					     krb5_creds *);

static int get_guid(char *,
		    uid_t *,
		    gid_t *);



/* Globals */
static char *progname;			/* This program's name */

/* Default options if we are authenticating from keytab */
#define KEYTAB_DEFAULT_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options if we are authenticating from cache */
#define CACHE_DEFAULT_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options for credentials for krb525d */
#define GATEWAY_DEFAULT_TKT_OPTIONS	0


int
main(argc, argv)
int argc;
char *argv[];
{
    struct sockaddr_in lsin, rsin;
    int sock, namelen;

    krb5_context context;
    krb5_auth_context auth_context = 0;

    krb5_data default_realm;

    krb5_data recv_data;
    krb5_data cksum_data;
    krb5_error_code retval;
    
    int resp_status;
    int exit_code = 0;

    /* Where the krb525d daemon is running */
    char *krb525_host = NULL;
    char **krb525_hosts = NULL;
    int krb525_host_num = 0;
    int krb525_port = -1;

    /* Credentials for authenticating to krb525d */
    char *krb525_cname = NULL;
    char *krb525_sname = KRB525_SERVICE;
    krb5_principal krb525_cprinc, krb525_sprinc;
    krb5_creds krb525_creds;
    krb5_flags gateway_options = GATEWAY_DEFAULT_TKT_OPTIONS;

    /* Credentials we are converting */
    char *cname = NULL;
    char *sname = NULL;
    krb5_principal cprinc, sprinc;

    /* Target credentials */
    char *target_cname = NULL;
    char *target_sname = NULL;
    krb5_principal target_cprinc, target_sprinc;
    krb5_creds target_creds;
    krb5_flags target_options = 0;

    /* Information about who should own target cache */
    char *cache_owner = NULL;
    uid_t uid = -1;
    gid_t gid = -1;

    /* Where we're going to put the converted credentials */
    krb5_ccache target_ccache = NULL;
    char *target_cache_name = NULL;
    krb5_boolean initialize_cache = 1;

    /* Where our credentials are */
    char *source_cache_name = NULL;
    krb5_ccache source_ccache = NULL;
    int use_keytab = 0;
    char *keytab_name = NULL;

#ifdef AFS_KRB5
    /* Are we running aklog */
    krb5_boolean run_aklog = 0;
    krb5_boolean dont_run_aklog = 0;
#endif /* AFS_KRB5 */
	
    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;

    krb5_data message;

    int arg;
    int arg_error = 0;

    int verbose = 0;



    /* Get our name, removing preceding path */
    if (progname = strrchr(argv[0], '/'))
	progname++;
    else
	progname = argv[0];

    /* Process arguments */
    while ((arg = getopt(argc, argv, "aAc:C:g:h:i:ko:p:s:S:t:u:vV")) != EOF)
	switch (arg) {
	case 'a':
#ifdef AFS_KRB5
	    run_aklog = 1;
#else
	    fprintf(stderr, "%s: -a option not supported\n", progname);
	    arg_error++;
#endif
	    break;

	case 'A':
#ifdef AFS_KRB5
	    dont_run_aklog = 1;
#else
	    fprintf(stderr, "%s: ignoring -A, not supported\n", progname);
#endif
	    break;


	case 'c':
	    cname = optarg;
	    break;

	case 'C':
	    target_cname = optarg;
	    break;

	case 'h':
	    krb525_host = optarg;
	    break;

	case 'i':
	    source_cache_name = optarg;
	    break;

	case 'k':
	    use_keytab = 1;
	    break;

	case 'o':
	    target_cache_name = optarg;
	    break;

	case 'p':
	    krb525_port = atoi(optarg);
	    if (krb525_port == 0) {
		fprintf(stderr, "Illegal port value \"%s\"\n", optarg);
		arg_error++;
	    }
	    break;

	case 's':
	    sname = optarg;
	    break;

	case 'S':
	    target_sname = optarg;
	    break;

	case 't':
	    keytab_name = optarg;
	    break;

	case 'u':
	    cache_owner = optarg;
	    break;

	case 'v':
	    verbose++;
	    break;

	case 'V':
	    printf("%s Version %s\n", progname, KRB525_VERSION_STRING);
	    exit(0);

	default:
	    arg_error++;
	    break;
	}

    if ((argc - optind) != 0)
	fprintf(stderr,
		"%s: Ignoring extra command line options starting with %s\n",
		progname, argv[optind]);

    if (keytab_name && !use_keytab) {
	fprintf(stderr,
		"%s: Need to specify keytab (-k) to use keytab name (-t)\n",
		progname);
	arg_error++;
    }

    if (use_keytab && !cname) {
	fprintf(stderr,
		"%s: Need to specify client name (-c) when using keytab (-k)\n",
		progname);
	arg_error++;
    }

#ifdef AFS_KRB5
    if (run_aklog && dont_run_aklog) {
	fprintf(stderr,	"%s: Cannot specify both -a and -A\n", progname);
	arg_error++;
    }
#endif /* AFS_KRB5 */

    if (arg_error) {
	fprintf(stderr, "Usage: %s [<options>]\n"
		" Options are:\n"
#ifdef AFS_KRB5
		"   -a                       Run aklog after acquiring new credentials\n"
		"   -A                       Do not run aklog\n"
#endif /* AFS_KRB5 */
		"   -c <client name>         Client for credentials to convert\n"
		"   -C <target client>       Client to convert to\n"
		"   -h <server host>         Host where server is running\n"
		"   -i <input cache>         Specify cache to get credentials from\n"
		"   -k                       Use key from keytab to authenticate\n"
		"   -o <output cache>        Cache to write credentials out to\n"
		"   -p <server port>         Port where server is running\n"
		"   -s <service name>        Service for credentials to convert\n"
		"   -S <target service>      Service to convert to\n"
		"   -t <keytab file>         Keytab file to use\n"
		"   -u <username>            Specify owner of output cache\n"
		"   -v                       Verbose mode\n"
		"   -V                       Print version and exit\n",
		progname);
	exit(1);
    }


    /* Kerberos initialization */
    if (verbose)
	printf("Initializing Kerberos\n");

    retval = krb5_init_context(&context);
    if (retval) {
	com_err(progname, retval, "while initializing krb5");
	error_exit();
    }

    /* XXX Why is this signal() call here? */
    (void) signal(SIGPIPE, SIG_IGN);

    if (!valid_cksumtype(CKSUMTYPE_CRC32)) {
	com_err(progname, KRB5_PROG_SUMTYPE_NOSUPP, "while using CRC-32");
	error_exit();
    }

    /*
     * Set default ticket options
     */
    if (use_keytab)
	target_options |= KEYTAB_DEFAULT_TKT_OPTIONS;
    else
	target_options |= CACHE_DEFAULT_TKT_OPTIONS;

    /*
     * Get our cache ready for use if appropriate.
     */
    if (!use_keytab) {
	if (source_cache_name)
	    retval = krb5_cc_resolve(context, source_cache_name,
				     &source_ccache);
	else
	    retval = krb5_cc_default(context, &source_ccache);

	if (retval) {
	    com_err(progname, retval, "resolving source cache %s",
		    (source_cache_name ? source_cache_name : "(default)"));
	    error_exit();
	}
    }

    /*
     * Get our default realm
     */
    if (retval = krb5_get_default_realm(context, &(default_realm.data))) {
	com_err(progname, retval, "resolving default realm");
	error_exit();
    }

    default_realm.length = strlen(default_realm.data);


    /*
     * If neither a target client name or target service name was
     * given, then target ticket is for current username
     */
    if (!target_cname && !target_sname) {
	struct passwd *pwd;

	pwd = getpwuid(geteuid());

	if (!pwd) {
	    perror("Password entry lookup failed");
	    error_exit();
	}

	target_cname = strdup(pwd->pw_name);
    }


    /*
     * Parse our client name. If none was given then use default for
     * our cache.
     */
    if (!use_keytab) {
	if (retval = krb5_cc_get_principal(context, source_ccache, &cprinc)) {
	    com_err(progname, retval, "while getting principal from cache");
	    error_exit();
	}
    } else {
	/* Client name must be provided with keytab. */
	if (retval = krb5_parse_name (context, cname, &cprinc)) {
	 com_err (progname, retval, "when parsing name %s", cname);
	 error_exit();
	}
    }
 	
    if (retval = krb5_unparse_name(context, cprinc, &cname)) {
	com_err (progname, retval, "when unparsing client");
	error_exit();
    }

    /*
     * Parse service name. If none was given then use krbtgt/<realm>@<realm>
     */
    if (sname == NULL) {
	if (retval = krb5_build_principal(context,
					  &sprinc,
					  default_realm.length,
					  default_realm.data,
					  KRB5_TGS_NAME,
					  default_realm.data,
					  0)) {
	    com_err (progname, retval,
		     "building default service principal");
	    error_exit();
	}
    } else {
	/* Service specified */
	if (retval = krb5_parse_name (context, sname, &sprinc)) {
	 com_err (progname, retval, "when parsing name %s", sname);
	 error_exit();
	}
    }
   
    if (retval = krb5_unparse_name(context, sprinc, &sname)) {
	 com_err (progname, retval, "when unparsing service");
	 error_exit();
    }

    /*
     * Parse our target client name. If none was given then use our
     * original client name.
     */
    if (!target_cname)
	target_cname = cname;

    /* Client name must be provided with keytab. */
    if (retval = krb5_parse_name (context, target_cname, &target_cprinc)) {
	com_err (progname, retval, "when parsing name %s", target_cname);
	error_exit();
    }
 	
    if (retval = krb5_unparse_name(context, target_cprinc, &target_cname)) {
	com_err (progname, retval, "when unparsing client");
	error_exit();
    }

    /*
     * Parse target service name. If none was given then use our original
     * service.
     */
    if (target_sname == NULL)
	target_sname = sname;

    /* Service specified */
    if (retval = krb5_parse_name (context, target_sname, &target_sprinc)) {
	com_err (progname, retval, "when parsing name %s", target_sname);
	error_exit();
    }
   
    if (retval = krb5_unparse_name(context, target_sprinc, &target_sname)) {
	com_err (progname, retval, "when unparsing service");
	error_exit();
    }


    if (verbose) {
	printf("Ticket to convert is %s for %s\n", cname, sname);
	printf("Target ticket is %s for %s\n", target_cname, target_sname);
    }

    /*
     * Ok, do we actually have anything to do?
     */
    if (krb5_principal_compare(context, cprinc, target_cprinc) &&
	krb5_principal_compare(context, sprinc, target_sprinc)) {
	fprintf(stderr, "%s: Nothing to do\n", progname);
	error_exit();
    }

    /*
     * Figure out our target cache. If we were given one then use
     * that. If no and we're were given a source cache then use that,
     * otherwise use the default.
     */
    if (!target_cache_name && source_cache_name)
	target_cache_name = source_cache_name;

    if (target_cache_name)
	retval = krb5_cc_resolve(context, target_cache_name,
				     &target_ccache);
    else
	retval = krb5_cc_default(context, &target_ccache);

    if (retval) {
	com_err(progname, retval, "resolving target cache %s",
		(target_cache_name ? target_cache_name : "(default)"));
	error_exit();
    }

    if (!target_cache_name) {
	target_cache_name = krb5_cc_default_name(context);

	if (strncmp(target_cache_name, "FILE:", 5) == 0)
	    target_cache_name += 5;
    }

    /*
     * Get and parse client name to authenticate to krb525d with. If none
     * specified then use our original client name.
     */
    if (krb525_cname == NULL)
	krb525_cname = cname;

    if (retval = krb5_parse_name (context, krb525_cname, &krb525_cprinc)) {
	com_err (progname, retval, "when parsing name %s", krb525_cname);
	error_exit();
    }

    if (retval = krb5_unparse_name(context, krb525_cprinc, &krb525_cname)) {
	com_err (progname, retval, "when unparsing krb525 client principal");
	error_exit();
    }

    /*
     * If we're creating a new cache, figure out who should own it. If a
     * user was specified on the command line then use that user.
     */
    if (cache_owner) {	
	if (get_guid(cache_owner, &uid, &gid)) {
	    fprintf(stderr,
		    "Could not resolve uid and gid for %s\n", cache_owner);
	    perror("User lookup");
	    error_exit();
	}
    } else {
	/*
	 * If we're using a keytab, or if the target client differs from
	 * the original client then try to set the ownership to the
	 * target client, but fail silently.
	 *
	 * Not 100% sure this is what is desired, but we'll try it for now.
	 */
	if (use_keytab || strcmp(cname, target_cname)) {
	    char *realm;

	    cache_owner = strdup(target_cname);

	    if (realm = strchr(cache_owner, '@'))
		*realm = '\0';
	    
	    if (get_guid(cache_owner, &uid, &gid)) {
		/* Fail silently */
		uid = -1;
		gid = -1;
	    }
	}
    }
 
    /* Get credentials to converted */
    if (use_keytab)
	retval = get_creds_with_keytab(context, cprinc, sprinc, target_options,
				       keytab_name, &target_creds);
    else
	retval = get_creds_with_ccache(context, cprinc, sprinc, target_options,
				       source_cache_name, &target_creds);

    if (retval) {
	/* Detailed error message already printed */
	fprintf(stderr, "Couldn't get ticket - %s for %s",
		cname, sname);
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

    /*
     * Figure out hostname(s) of server(s). If user supplied a hostname, then
     * use that. Otherwise try all the Kerberos servers for this realm.
     */
    if (krb525_host) {
	/* User provided a hostname, so build list from that */
	krb525_hosts = (char **) malloc( 2 * sizeof(char *));

	if (!krb525_hosts) {
	    perror("malloc() failed");
	    error_exit();
	}

	krb525_hosts[0] = strdup(krb525_host);
	krb525_hosts[1] = NULL;

    } else {
	if (retval = krb5_get_krbhst(context, &default_realm, &krb525_hosts)) {
	    com_err(progname, retval,
		    "getting list of kerberos servers for realm %s",
		    default_realm.data);
	    error_exit();
	}

	if (!krb525_hosts || !krb525_hosts[0]) {
	    fprintf(stderr, "Couldn't figure out name of kerberos server host");
	    error_exit();
	}
    }

    krb525_host_num = 0;

    while (krb525_host = krb525_hosts[krb525_host_num]) {
	/* Connect to the server */
	if (verbose)
	    printf("Trying to connect to krb525d on %s port %d\n",
		   krb525_host, krb525_port);

	if ((sock = connect_to_server(krb525_host, krb525_port)) > 0 )
	    break; /* Success */

	if (verbose)
	    printf("Connection failed: %s\n", strerror(errno));

	krb525_host_num++;
    }

    if (sock < 0) {
	fprintf(stderr, "Couldn't connect to krb525d.\n");
	error_exit();
    }

    if (verbose)
	printf("Connected to %s\n", krb525_host);

    /*
     * Parse service name to authenticate with. (Default is
     * KRB525_SERVICE/<hostname>)
     */
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

    /* Get our credentials for the gateway */
    if (verbose)
	printf("Getting credentials for krb525d (%s for %s)\n",
	       krb525_cname, krb525_sname);

    if (use_keytab)
	retval = get_creds_with_keytab(context, krb525_cprinc, krb525_sprinc,
				       gateway_options, keytab_name,
				       &krb525_creds);
    else
	retval = get_creds_with_ccache(context, krb525_cprinc, krb525_sprinc,
				       gateway_options, source_cache_name,
				       &krb525_creds);

    if (retval) {
	/* Detailed error message already printed */
	fprintf(stderr, "Couldn't get ticket - %s for %s\n",
		 krb525_cname, krb525_sname);
	error_exit();
    }
    
    /* Authenticate to server */
    if (verbose)
	printf("Authenticating...\n");

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

    /* Prepare to encrypt */
    if (retval = setup_auth_context(context, auth_context, sock,
				     progname)) {
	com_err(progname, retval, auth_con_error);
	error_exit();
    }

    /* Send target client name */
    message.data = target_cname;
    message.length = strlen(target_cname) + 1;

    if (retval = send_encrypt(context, auth_context, sock, message)) {
	fprintf(stderr, "%s sending target client name\n", netio_error);
	error_exit();
    }

    /* Send target server name */
    message.data = target_sname;
    message.length = strlen(target_sname) + 1;

    if (retval = send_encrypt(context, auth_context, sock, message)) {
	fprintf(stderr, "%s sending target server name\n", netio_error);
	error_exit();
    }
 
    /* Set my ticket to be massaged */
    message.data = target_creds.ticket.data;
    message.length = target_creds.ticket.length;

    if (retval = send_encrypt(context, auth_context, sock, message)) {
	fprintf(stderr, "%s sending ticket to convert\n", netio_error);
	error_exit();
    }
 
    /* Read reply */
    if ((retval = read_msg(context, sock, &recv_data)) < 0) {
	fprintf(stderr, "%s reading reply\n", netio_error);
	error_exit();
    }
    
    resp_status = *((int *) recv_data.data);

    switch(resp_status) {
    case STATUS_OK:
	/* Read new ticket from server */
	if ((retval = read_encrypt(context, auth_context, sock, &recv_data))
	    < 0) {
	    fprintf(stderr, "%s reading ticket\n", netio_error);
	    error_exit();
	}

	if (verbose)
	    printf("New ticket read from server. Storing in %s\n",
		   target_cache_name);

	/* Put new ticket data into credentials */
	target_creds.ticket.data = recv_data.data;
	target_creds.ticket.length = recv_data.length;

	/* Massage other fields of credentials */
	target_creds.client = target_cprinc;

	/* Ok now store the ticket */

	/*
	 * Decide if we initialize the cache. If we came from a keytab or
	 * we changed clients, or the target cache != source cache then
	 * initialize the cache.
	 *
	 * XXX - Not 100% sure this is right.
	 */
	if (use_keytab ||
	    strcmp(cname, target_cname) ||
	    !source_cache_name ||
	    source_cache_name && strcmp(source_cache_name, target_cache_name))
	    initialize_cache = 1;

	if (initialize_cache) {
	    if (verbose)
		printf("Initializing cache\n");

	    if (retval = krb5_cc_initialize(context, target_ccache,
					 target_cprinc)) {
		com_err(progname, retval, "initializing cache");
		error_exit();
	    }
	}

	if (retval = krb5_cc_store_cred(context, target_ccache, &target_creds)) {
	    com_err(progname, retval, "storing credentials");
	    error_exit();
	}

	if (verbose && (uid != -1))
	    printf("Changing owner of credentials cache to %s\n",
		   cache_owner);

	if (chown(target_cache_name, uid, gid)) {
	    perror("Setting owner of credentials cache");
	    error_exit();
	}

#ifdef AFS_KRB5	
	/*
	 * If we weren't explicitly told not to run or not to run
	 * aklog then check the configuration file.
	 */
	if (!run_aklog && !dont_run_aklog)
	    krb5_appdefault_boolean(context, progname, &default_realm,
				    "krb5_run_aklog", 0, (int *) &run_aklog);

	if (run_aklog) {
	    char *aklog_path;
	    struct stat st;

	    krb5_appdefault_string(context, progname, &default_realm,
				   "krb5_aklog_path", INSTALLPATH "bin/aklog",
				   &aklog_path);

	    /*
	     * Make sure it exists before we try to run it
	     */
	    if (stat(aklog_path, &st) == 0) {
		if (verbose)
		    printf("Running %s\n", aklog_path);

		system(aklog_path);
	    } else {
		if (verbose)
		    printf("Can't run aklog: %s doesn't exist",
			   aklog_path);
	    }

	    free(aklog_path);
	}	
#endif /* AFS_KRB5 */

	break;

    case STATUS_ERROR:	
	/* Read and print error message from server */
	if ((retval = read_encrypt(context, auth_context, sock, &recv_data))
	    < 0) {
	    fprintf(stderr, "%s reading error message\n", netio_error);
	    error_exit();
	}

        printf("%s: %s\n", progname, recv_data.data);
	break;

    default:
	printf("Unknown response status %d\n", resp_status);
    }

cleanup:
    /* XXX - lots of cleanup should be done here */

    if (krb525_hosts)
	krb5_free_krbhst(context, krb525_hosts);

    if (sock > 0)
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
		      krb5_flags options,
		      char *keytab_name,
		      krb5_creds *creds)
{
    krb5_error_code	retval;
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
		      krb5_flags options,
		      char *cache_name,
		      krb5_creds *creds)
{
    krb5_error_code	retval;
    krb5_address 	**addrs = (krb5_address **)0;
    krb5_preauthtype 	*preauth = NULL;
    krb5_preauthtype 	preauth_list[2] = { 0, -1 };
    krb5_ccache		ccache;
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


