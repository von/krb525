/*
 * client.c
 *
 * krb525 client program
 *
 * $Id: client.c,v 1.20 2000/02/23 17:20:15 vwelch Exp $
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


/* For exiting with error in main() */
#define error_exit()	{ exit_code = 1; goto cleanup; }



typedef struct _krb525_client_context {
    krb5_context		krb5_context;
    krb5_auth_context		auth_context;
    krb5_data			default_realm;

    /* This program's name */
    char			*progname;

    /* Are we running in verbose mode? */
    int				verbose;

    /* Where the deamon is running */
    char			*krb525d_host;
    int				krb525d_port;
    int				krb525d_sock;

    /* Credentials for authenticating to krb525d */
    char			*krb525_cname;
    char			*krb525_sname;
    krb5_principal		krb525_cprinc;
    krb5_principal		krb525_sprinc;
    krb5_creds			krb525_creds;
    krb5_flags			krb525_tkt_options;

    /* Credentials we are converting */
    krb5_creds			creds;
    krb5_flags			cred_options;

    /* Initial credential client and service */
    char			*cname;
    char			*sname;
    krb5_principal		cprinc;
    krb5_principal		sprinc;

    /* Target credential cleint and service */
    char			*target_cname;
    char			*target_sname;
    krb5_principal		target_cprinc;
    krb5_principal		target_sprinc;

    /* Where we get the credentials from */
    int				use_keytab;
    char			*source_cache_name;
    krb5_ccache			source_ccache;
    char			*keytab_name;

    /* Where we put the converted credentials */
    krb5_ccache			target_ccache;
    char			*target_cache_name;
    krb5_boolean		initialize_cache;
    krb5_boolean		dont_initialize_cache;

    /* Do we chown the target cache, and who should own it */
    krb5_boolean		chown_target_cache;
    krb5_boolean		dont_chown_target_cache;
    char			*target_cache_owner;
    uid_t			target_cache_uid;
    gid_t			target_cache_gid;

#ifdef AFS_KRB5
    /* Are we running aklog */
    krb5_boolean		run_aklog;
    krb5_boolean		dont_run_aklog;
#endif /* AFS_KRB5 */
	

} krb525_client_context;


static int parse_commandline(krb525_client_context *,
			     int,
			     char **);

static krb5_error_code get_creds(krb525_client_context *,
				 krb5_principal,
				 krb5_principal,
				 krb5_flags,
				 krb5_creds *);

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

static int connect_to_krb525d(krb525_client_context *);

static krb5_error_code setup_caches(krb525_client_context *);

static krb5_error_code setup_principals(krb525_client_context *);

static krb5_error_code authenticate_to_krb525d(krb525_client_context *);

static krb5_error_code store_converted_ticket(krb525_client_context *,
					      krb5_data *);

static krb5_boolean should_initialize_target_cache(krb525_client_context *);

static krb5_boolean should_chown_target_cache(krb525_client_context *);

static krb5_boolean is_tgt(krb525_client_context *,
			   krb5_principal);

static int get_guid(char *,
		    uid_t *,
		    gid_t *);


#ifdef AFS_KRB5
static krb5_boolean should_run_aklog(krb525_client_context *my_context);

static krb5_boolean is_afs_service(krb525_client_context *,
				   krb5_principal);

static void run_aklog(krb525_client_context *);
#endif /* AFS_KRB5 */


/* Default options if we are authenticating from keytab */
#define DEFAULT_KEYTAB_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options if we are authenticating from cache */
#define DEFAULT_CACHE_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options for credentials for krb525d */
#define DEFAULT_KRB525_TKT_OPTIONS	0



int
main(argc, argv)
int argc;
char *argv[];
{
    krb525_client_context	my_context;

    krb5_data recv_data;
    krb5_error_code retval;
    
    int resp_status;
    int exit_code = 0;

    krb5_data message;



    /* Initialize my context */
    memset(&my_context, 0, sizeof(my_context));

    my_context.krb525d_port = -1;
    my_context.krb525d_sock = -1;
    my_context.krb525_sname = KRB525_SERVICE;
    my_context.krb525_tkt_options = DEFAULT_KRB525_TKT_OPTIONS;


    if (parse_commandline(&my_context,
			  argc,
			  argv)) {
	/* Error message already printed */
	error_exit();
    }

    /* Kerberos initialization */
    if (my_context.verbose)
	printf("Initializing Kerberos\n");

    retval = krb5_init_context(&(my_context.krb5_context));
    if (retval) {
	com_err(my_context.progname, retval, "while initializing krb5");
	error_exit();
    }

    /*
     * Ignore SIGPIPEs that get thrown because the server died on us.
     */
    (void) signal(SIGPIPE, SIG_IGN);

    if (!valid_cksumtype(CKSUMTYPE_CRC32)) {
	com_err(my_context.progname, KRB5_PROG_SUMTYPE_NOSUPP,
		"while using CRC-32");
	error_exit();
    }

    /*
     * Set default ticket options
     */
    if (my_context.use_keytab)
	my_context.cred_options |= DEFAULT_KEYTAB_TKT_OPTIONS;
    else
	my_context.cred_options |= DEFAULT_CACHE_TKT_OPTIONS;

    /*
     * Get our cache(s) ready for use
     */
    if (setup_caches(&my_context)) {
	/* Error message already printed */
	error_exit();
    }

    /*
     * Get our default realm
     */
    if (retval = krb5_get_default_realm(my_context.krb5_context,
					&(my_context.default_realm.data))) {
	com_err(my_context.progname, retval, "resolving default realm");
	error_exit();
    }

    my_context.default_realm.length = strlen(my_context.default_realm.data);


    /*
     * If neither a target client name or target service name was
     * given, then target ticket is for current username
     */
    if (!my_context.target_cname && !my_context.target_sname) {
	struct passwd *pwd;

	pwd = getpwuid(geteuid());

	if (!pwd) {
	    perror("Password entry lookup failed");
	    error_exit();
	}

	my_context.target_cname = strdup(pwd->pw_name);
    }


    if (setup_principals(&my_context)) {
	/* Error message already printed */
	error_exit();
    }
 
    if (my_context.verbose) {
	printf("Ticket to convert is %s for %s\n",
	       my_context.cname, my_context.sname);
	printf("Target ticket is %s for %s\n",
	       my_context.target_cname, my_context.target_sname);
    }

    /*
     * Ok, do we actually have anything to do?
     */
    if (krb5_principal_compare(my_context.krb5_context,
			       my_context.cprinc,
			       my_context.target_cprinc) &&
	krb5_principal_compare(my_context.krb5_context,
			       my_context.sprinc,
			       my_context.target_sprinc)) {
	fprintf(stderr, "%s: Nothing to do\n", my_context.progname);
	error_exit();
    }

    /*
     * Should we initialize the target cache?
     */
    my_context.initialize_cache = should_initialize_target_cache(&my_context);

    /*
     * Figure out if we should chown the target credentials cache
     */

    my_context.chown_target_cache = should_chown_target_cache(&my_context);

    /*
     * Figure out uid and gid that we whould be chowning target cache to
     */
    if (my_context.chown_target_cache) {	
	if (my_context.verbose)
	    printf("Looking up uid and gid for %s for chowning cache\n",
		   my_context.target_cache_owner);

	if (get_guid(my_context.target_cache_owner,
		     &my_context.target_cache_uid,
		     &my_context.target_cache_gid)) {
	    fprintf(stderr,
		    "Could not resolve uid and gid for %s\n",
		    my_context.target_cache_owner);
	    perror("User lookup");
	    error_exit();
	}
    }

#ifdef AFS_KRB5
    /* Should we run aklog? */
    my_context.run_aklog = should_run_aklog(&my_context);
#endif /* AFS_KRB5 */

    /* Get credentials to converted */
    retval = get_creds(&my_context,
		       my_context.cprinc,
		       my_context.sprinc,
		       my_context.cred_options,
		       &my_context.creds);

    if (retval) {
	/* Detailed error message already printed */
	fprintf(stderr, "Couldn't get ticket - %s for %s",
		my_context.cname, my_context.sname);
	error_exit();
    }

    /* Connect to krb525d */
    if (connect_to_krb525d(&my_context)) {
	/* Error message already printed */
	error_exit();
    }

    /* And authenticate */
    if (authenticate_to_krb525d(&my_context)) {
	/* Error message already printed */
	error_exit();
    }

    /* Prepare to encrypt */
    if (retval = setup_auth_context(my_context.krb5_context,
				    my_context.auth_context,
				    my_context.krb525d_sock,
				    my_context.progname)) {
	com_err(my_context.progname, retval, auth_con_error);
	error_exit();
    }

    /* Send target client name */
    message.data = my_context.target_cname;
    message.length = strlen(my_context.target_cname) + 1;

    if (retval = send_encrypt(my_context.krb5_context,
			      my_context.auth_context,
			      my_context.krb525d_sock,
			      message)) {
	fprintf(stderr, "%s sending target client name\n", netio_error);
	error_exit();
    }

    /* Send target server name */
    message.data = my_context.target_sname;
    message.length = strlen(my_context.target_sname) + 1;

    if (retval = send_encrypt(my_context.krb5_context,
			      my_context.auth_context,
			      my_context.krb525d_sock,
			      message)) {
	fprintf(stderr, "%s sending target server name\n", netio_error);
	error_exit();
    }
 
    /* Set my ticket to be massaged */
    message.data = my_context.creds.ticket.data;
    message.length = my_context.creds.ticket.length;

    if (retval = send_encrypt(my_context.krb5_context,
			      my_context.auth_context,
			      my_context.krb525d_sock,
			      message)) {
	fprintf(stderr, "%s sending ticket to convert\n", netio_error);
	error_exit();
    }
 
    /* Read reply */
    retval = read_value(my_context.krb5_context,
			my_context.krb525d_sock,
			&resp_status);

    if (retval < 0) {
	fprintf(stderr, "%s reading reply\n", netio_error);
	error_exit();
    }

    switch(resp_status) {
    case STATUS_OK:
	/* Read new ticket from server */
	if (my_context.verbose)
	    printf("Success. Reading converted ticket from server\n");

	if ((retval = read_encrypt(my_context.krb5_context,
				   my_context.auth_context,
				   my_context.krb525d_sock,
				   &recv_data))
	    < 0) {
	    fprintf(stderr, "%s reading ticket\n", netio_error);
	    error_exit();
	}

	if (store_converted_ticket(&my_context,
				   &recv_data)) {
	    /* Error message already printed */
	    error_exit();
	}

	if (my_context.chown_target_cache) {
	    printf("Changing owner of credentials cache to %s (uid = %d gid = %d\n",
		   my_context.target_cache_owner,
		   my_context.target_cache_uid,
		   my_context.target_cache_gid);

	    if (chown(my_context.target_cache_name,
		      my_context.target_cache_uid,
		      my_context.target_cache_gid)) {
		perror("Setting owner of credentials cache");
		error_exit();
	    }
	}

#ifdef AFS_KRB5	
	if (my_context.run_aklog)
	    run_aklog(&my_context);
#endif /* AFS_KRB5 */

	break;

    case STATUS_ERROR:	
	/* Read and print error message from server */
	if ((retval = read_encrypt(my_context.krb5_context,
				   my_context.auth_context,
				   my_context.krb525d_sock,
				   &recv_data)) < 0) {
	    fprintf(stderr, "%s reading error message\n", netio_error);
	    error_exit();
	}

        printf("%s: %s\n", my_context.progname, recv_data.data);
	break;

    default:
	printf("Unknown response status %d\n", resp_status);
    }

cleanup:
    /* XXX - lots of cleanup should be done here */

    if (my_context.krb525d_sock > 0)
	close(my_context.krb525d_sock);

    if (my_context.verbose)
	printf("Done\n");

    /* XXX Need to cleanup exit code */
    exit(resp_status);
}


/*
 * Parse commandline options
 *
 * Returns non-zero on error.
 */
static int
parse_commandline(krb525_client_context *my_context,
		  int			argc,
		  char			*argv[])
{
    int					arg;
    int					arg_error = 0;
    char				*options_string;


    options_string = "aAc:C:g:h:i:knNo:p:s:S:t:u:UvV";

    /* Get our name, removing preceding path */
    if (my_context->progname = strrchr(argv[0], '/'))
	my_context->progname++;
    else
	my_context->progname = argv[0];

    /* Process arguments */
    while ((arg = getopt(argc, argv, options_string)) != EOF)
	switch (arg) {
	case 'a':
#ifdef AFS_KRB5
	    my_context->run_aklog = 1;
#else
	    fprintf(stderr, "%s: -a option not supported\n", progname);
	    arg_error++;
#endif
	    break;

	case 'A':
#ifdef AFS_KRB5
	    my_context->dont_run_aklog = 1;
#else
	    fprintf(stderr, "%s: ignoring -A, not supported\n", progname);
#endif
	    break;


	case 'c':
	    my_context->cname = optarg;
	    break;

	case 'C':
	    my_context->target_cname = optarg;
	    break;

	case 'h':
	    my_context->krb525d_host = optarg;
	    break;

	case 'i':
	    my_context->source_cache_name = optarg;
	    break;

	case 'k':
	    my_context->use_keytab = 1;
	    break;

	case 'n':
	    my_context->initialize_cache = 1;
	    break;

	case 'N':
	    my_context->dont_initialize_cache = 1;
	    break;

	case 'o':
	    my_context->target_cache_name = optarg;
	    break;

	case 'p':
	    my_context->krb525d_port = atoi(optarg);
	    if (my_context->krb525d_port == 0) {
		fprintf(stderr, "Illegal port value \"%s\"\n", optarg);
		arg_error++;
	    }
	    break;

	case 's':
	    my_context->sname = optarg;
	    break;

	case 'S':
	    my_context->target_sname = optarg;
	    break;

	case 't':
	    my_context->keytab_name = optarg;
	    break;

	case 'u':
	    my_context->target_cache_owner = optarg;
	    my_context->chown_target_cache = 1;
	    break;

	case 'U':
	    my_context->dont_chown_target_cache = 1;
	    break;

	case 'v':
	    my_context->verbose++;
	    break;

	case 'V':
	    printf("%s Version %s\n", my_context->progname, KRB525_VERSION_STRING);
	    exit(0);

	default:
	    arg_error = 1;
	}

    if ((argc - optind) != 0)
	fprintf(stderr,
		"%s: Ignoring extra command line options starting with %s\n",
		my_context->progname, argv[optind]);

    if (my_context->keytab_name && !my_context->use_keytab) {
	fprintf(stderr,
		"%s: Need to specify keytab (-k) to use keytab name (-t)\n",
		my_context->progname);
	arg_error = 1;
    }

    if (my_context->use_keytab && !my_context->cname) {
	fprintf(stderr,
		"%s: Need to specify client name (-c) when using keytab (-k)\n",
		my_context->progname);
	arg_error = 1;
    }

    if (my_context->initialize_cache && my_context->dont_initialize_cache) {
	fprintf(stderr, "%s: Connect specify both -n and -N\n",
		my_context->progname);
	arg_error = 1;
    }
    
    if (my_context->chown_target_cache && my_context->dont_chown_target_cache) {
	fprintf(stderr, "%s: Connect specify both -u and -U\n",
		my_context->progname);
	arg_error = 1;
    }

#ifdef AFS_KRB5
    if (my_context->run_aklog && my_context->dont_run_aklog) {
	fprintf(stderr,	"%s: Cannot specify both -a and -A\n",
		my_context->progname);
	arg_error = 1;
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
		"   -n                       Initialize target cache\n"
		"   -N                       Don't initialize target cache\n"
		"   -o <output cache>        Cache to write credentials out to\n"
		"   -p <server port>         Port where server is running\n"
		"   -s <service name>        Service for credentials to convert\n"
		"   -S <target service>      Service to convert to\n"
		"   -t <keytab file>         Keytab file to use\n"
		"   -u <username>            Specify owner of output cache\n"
		"   -U                       Don't chown output cache\n"
		"   -v                       Verbose mode\n"
		"   -V                       Print version and exit\n",
		my_context->progname);
    }

    return arg_error;
}



/*
 * Get credentials using keytab or cache as indicated
 *
 * Returns non-zero on error.
 */
static krb5_error_code
get_creds(krb525_client_context *my_context,
	  krb5_principal	client,
	  krb5_principal	server,
	  krb5_flags		options,
	  krb5_creds		*creds)
{
    krb5_error_code		retval;


    if (my_context->use_keytab)
	retval = get_creds_with_keytab(my_context->krb5_context,
				       client,
				       server,
				       options,
				       my_context->keytab_name,
				       creds);
    else
	retval = get_creds_with_ccache(my_context->krb5_context,
				       client,
				       server,
				       options,
				       my_context->source_cache_name,
				       creds);

    return retval;
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
    char *progname = "DUH";	/* XXX */


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
    char *progname = "DUH";	/* XXX */

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
 * Connect to the krb525d daemon
 *
 * Returns -1 on error, 0 otherwise
 */
static int
connect_to_krb525d(krb525_client_context *my_context)
{
    char		**krb525d_hosts = NULL;
    int			krb525_host_num = 0;
    char		*krb525d_host;
    int			status = -1;
    krb5_error_code	retval;


    /* Figure out the port number of the server */
    if (my_context->krb525d_port == -1) {
	/* User didn't specify a port */
	struct servent *sp;
	sp = getservbyname(KRB525_SERVICE, "tcp");
	if (sp) {
	    my_context->krb525d_port = sp->s_port;
	} else {
	    my_context->krb525d_port = KRB525_PORT;
	}
    }

    /*
     * Figure out hostname(s) of server(s). If user supplied a hostname, then
     * use that. Otherwise try all the Kerberos servers for this realm.
     */
    if (my_context->krb525d_host) {
	/* User provided a hostname, so build list from that */
	krb525d_hosts = (char **) malloc( 2 * sizeof(char *));

	if (!krb525d_hosts) {
	    perror("malloc() failed");
	    goto cleanup;
	}

	krb525d_hosts[0] = strdup(my_context->krb525d_host);
	krb525d_hosts[1] = NULL;

    } else {
	if (retval = krb5_get_krbhst(my_context->krb5_context,
				     &my_context->default_realm,
				     &krb525d_hosts)) {
	    com_err(my_context->progname, retval,
		    "getting list of kerberos servers for realm %s",
		    my_context->default_realm.data);
	    goto cleanup;
	}

	if (!krb525d_hosts || !krb525d_hosts[0]) {
	    fprintf(stderr, "Couldn't figure out name of kerberos server host");
	    goto cleanup;
	}
    }

    krb525_host_num = 0;

    while (krb525d_host = krb525d_hosts[krb525_host_num]) {
	/* Connect to the server */
	if (my_context->verbose)
	    printf("Trying to connect to krb525d on %s port %d\n",
		   krb525d_host, my_context->krb525d_port);

	if ((my_context->krb525d_sock =
	     connect_to_server(krb525d_host,
			       my_context->krb525d_port)) > 0 )
	    break; /* Success */

	if (my_context->verbose)
	    printf("Connection failed: %s\n", strerror(errno));

	krb525_host_num++;
    }

    if (my_context->krb525d_sock < 0) {
	fprintf(stderr, "Couldn't connect to krb525d.\n");
	goto cleanup;
    }

    /* Success */
    status = 0;

    my_context->krb525d_host = strdup(krb525d_host);

    if (my_context->verbose)
	printf("Connected to %s\n", my_context->krb525d_host);

 cleanup:
    if (krb525d_hosts)
	krb5_free_krbhst(my_context->krb5_context, krb525d_hosts);

    return status;
}



/*
 * Resolve input and output caches
 *
 * Returns non-zero on error
 */
static krb5_error_code
setup_caches(krb525_client_context *my_context)
{
    krb5_error_code		retval = 0;


    /* Input cache, if we're not using a keytab */
    if (!my_context->use_keytab) {
	if (my_context->source_cache_name)
	    retval = krb5_cc_resolve(my_context->krb5_context,
				     my_context->source_cache_name,
				     &my_context->source_ccache);
	else
	    retval = krb5_cc_default(my_context->krb5_context,
				     &my_context->source_ccache);

	if (retval) {
	    com_err(my_context->progname, retval, "resolving source cache %s",
		    (my_context->source_cache_name ?
		     my_context->source_cache_name :
		     "(default)"));
	    goto cleanup;
	}

	if (!my_context->source_cache_name) {
	    my_context->source_cache_name =
		krb5_cc_default_name(my_context->krb5_context);
	}
    }

    /* Output cache */
    if (my_context->target_cache_name)
	retval = krb5_cc_resolve(my_context->krb5_context,
				 my_context->target_cache_name,
				 &my_context->target_ccache);
    else
	retval = krb5_cc_default(my_context->krb5_context,
				 &my_context->target_ccache);

    if (retval) {
	com_err(my_context->progname, retval, "resolving target cache %s",
		(my_context->target_cache_name ?
		 my_context->target_cache_name :
		 "(default)"));
	goto cleanup;
    }

    if (!my_context->target_cache_name) {
	my_context->target_cache_name =
	    krb5_cc_default_name(my_context->krb5_context);
    }

 cleanup:
    return retval;
}



/*
 * Parse the principal names for the credentials.
 * Must be called after caches are setup.
 *
 * Returns non-zero on error
 */
static krb5_error_code
setup_principals(krb525_client_context *my_context)
{
    krb5_error_code		retval;


   /*
    * Parse our client name.
    */
    if (!my_context->use_keytab) {
	/* If we are using a cache, then that is our client name */
	if (retval = krb5_cc_get_principal(my_context->krb5_context,
					   my_context->source_ccache,
					   &my_context->cprinc)) {
	    com_err(my_context->progname, retval,
		    "while getting principal from cache");
	    goto cleanup;
	}
    } else {
	/* Client name must be provided with keytab. */
	if (retval = krb5_parse_name(my_context->krb5_context,
				     my_context->cname,
				     &my_context->cprinc)) {
	 com_err(my_context->progname, retval,
		  "when parsing name %s", my_context->cname);
	 goto cleanup;
	}
    }
 	
    if (retval = krb5_unparse_name(my_context->krb5_context, my_context->cprinc,
				   &my_context->cname)) {
	com_err (my_context->progname, retval, "when unparsing client");
	goto cleanup;
    }

   /*
     * Parse service name. If none was given then use krbtgt/<realm>@<realm>
     */
    if (my_context->sname == NULL) {
	if (retval = krb5_build_principal(my_context->krb5_context,
					  &my_context->sprinc,
					  my_context->default_realm.length,
					  my_context->default_realm.data,
					  KRB5_TGS_NAME,
					  my_context->default_realm.data,
					  0)) {
	    com_err(my_context->progname, retval,
		     "building default service principal");
	    goto cleanup;
	}
    } else {
	/* Service specified */
	if (retval = krb5_parse_name(my_context->krb5_context, my_context->sname,
				     &my_context->sprinc)) {
	 com_err(my_context->progname, retval,
		  "when parsing name %s", my_context->sname);
	 goto cleanup;
	}
    }
   
    if (retval = krb5_unparse_name(my_context->krb5_context, my_context->sprinc,
				   &my_context->sname)) {
	 com_err(my_context->progname, retval, "when unparsing service");
	 goto cleanup;
    }

    /*
     * Parse our target client name. If none was given then use our
     * original client name.
     */
    if (!my_context->target_cname)
	my_context->target_cname = my_context->cname;

    /* Client name must be provided with keytab. */
    if (retval = krb5_parse_name(my_context->krb5_context,
				 my_context->target_cname,
				 &my_context->target_cprinc)) {
	com_err(my_context->progname, retval,
		 "when parsing name %s", my_context->target_cname);
	goto cleanup;
    }
 	
    if (retval = krb5_unparse_name(my_context->krb5_context,
				   my_context->target_cprinc,
				   &my_context->target_cname)) {
	com_err (my_context->progname, retval, "when unparsing client");
	goto cleanup;
    }

    /*
     * Parse target service name. If none was given then use our original
     * service.
     */
    if (my_context->target_sname == NULL)
	my_context->target_sname = my_context->sname;

    /* Service specified */
    if (retval = krb5_parse_name(my_context->krb5_context,
				 my_context->target_sname,
				 &my_context->target_sprinc)) {
	com_err(my_context->progname, retval,
		 "when parsing name %s", my_context->target_sname);
	goto cleanup;
    }
   
    if (retval = krb5_unparse_name(my_context->krb5_context,
				   my_context->target_sprinc,
				   &my_context->target_sname)) {
	com_err(my_context->progname, retval, "when unparsing service");
	goto cleanup;
    }

 cleanup:
    return retval;
}



/*
 * Authenticate to krb525d
 *
 * Returns non-zero on error
 */
static krb5_error_code
authenticate_to_krb525d(krb525_client_context *my_context)
{
    krb5_error_code		retval;
    krb5_data			cksum_data;
    krb5_error			*err_ret;
    krb5_ap_rep_enc_part	*rep_ret;


    /*
     * Get and parse client name to authenticate to krb525d with. If none
     * specified then use our original client name.
     */
    if (my_context->krb525_cname == NULL)
	my_context->krb525_cname = my_context->cname;

    if (retval = krb5_parse_name(my_context->krb5_context,
				 my_context->krb525_cname,
				 &my_context->krb525_cprinc)) {
	com_err (my_context->progname, retval,
		 "when parsing name %s", my_context->krb525_cname);
	goto cleanup;
    }

    if (retval = krb5_unparse_name(my_context->krb5_context,
				   my_context->krb525_cprinc,
				   &my_context->krb525_cname)) {
	com_err(my_context->progname, retval,
		"when unparsing krb525 client principal");
	goto cleanup;
    }

    /*
     * Parse service name to authenticate with. (Default is
     * KRB525_SERVICE/<hostname>)
     */
    if (retval = krb5_sname_to_principal(my_context->krb5_context,
					 my_context->krb525d_host,
					 my_context->krb525_sname,
					 KRB5_NT_SRV_HST,
					 &my_context->krb525_sprinc)) {
	com_err(my_context->progname, retval,
		"while creating server name for %s/%s",
		my_context->krb525_sname, my_context->krb525d_host);
	goto cleanup;
    }

    if (retval = krb5_unparse_name(my_context->krb5_context,
				   my_context->krb525_sprinc,
				   &my_context->krb525_sname)) {
	com_err(my_context->progname, retval,
		"when unparsing krb525 service principal");
	goto cleanup;
    }



    /* Get our credentials for krb525d */
    if (my_context->verbose)
	printf("Getting credentials for krb525d (%s for %s)\n",
	       my_context->krb525_cname, my_context->krb525_sname);

    retval = get_creds(my_context,
		       my_context->krb525_cprinc,
		       my_context->krb525_sprinc,
		       my_context->krb525_tkt_options,
		       &my_context->krb525_creds);

    if (retval) {
	/* Detailed error message already printed */
	fprintf(stderr, "Couldn't get ticket - %s for %s\n",
		 my_context->krb525_cname, my_context->krb525_sname);
	goto cleanup;
    }
    
    /* Authenticate to server */
    if (my_context->verbose)
	printf("Authenticating...\n");

    /*
     * I have no idea what the cksum_data stuff is for or why it uses
     * the hostname of the server.
     */
    cksum_data.data = my_context->krb525d_host;
    cksum_data.length = strlen(my_context->krb525d_host);

    retval = krb5_sendauth(my_context->krb5_context,
			   &my_context->auth_context,
			   (krb5_pointer) &my_context->krb525d_sock,
			   KRB525_VERSION,
			   my_context->krb525_cprinc,	/* Not needed */
			   my_context->krb525_sprinc,	/* Not needed */
			   AP_OPTS_MUTUAL_REQUIRED,
			   &cksum_data,
			   &my_context->krb525_creds,
			   NULL, &err_ret, &rep_ret, NULL);

    if (retval && retval != KRB5_SENDAUTH_REJECTED) {
	com_err(my_context->progname, retval, "while using sendauth");
	goto cleanup;
    }

    if (retval == KRB5_SENDAUTH_REJECTED) {
	/* got an error */
	printf("sendauth rejected, error reply is:\n\t\"%*s\"\n",
	       err_ret->text.length, err_ret->text.data);
	goto cleanup;
    }

    if (rep_ret == NULL) {
	com_err(my_context->progname, 0, "no error or reply from sendauth!");
	goto cleanup;
    }

    if (my_context->verbose)
	printf("sendauth succeeded\n");

 cleanup:
    return retval;
}



/*
 * Store the converted ticket in the target cache.
 *
 * Returns non-zero on error.
 */
static krb5_error_code
store_converted_ticket(krb525_client_context *my_context,
		       krb5_data *converted_ticket)
{
    krb5_error_code retval;


    /* Put new ticket data into credentials */
    my_context->creds.ticket.data = converted_ticket->data;
    my_context->creds.ticket.length = converted_ticket->length;

    /* Massage other fields of credentials to match converted ticket */
    my_context->creds.client = my_context->target_cprinc;
    my_context->creds.server = my_context->target_sprinc;

    if (my_context->verbose)
	printf("Storing converted ticket in %s\n",
	       my_context->target_cache_name);

    /*
     * If we're not initializing the cache, then make sure the cache
     * exists and doesn't already contain a matching existing credential.
     */
    if (!my_context->initialize_cache) {
	krb5_flags		retrieve_flags = 0;
	krb5_creds		found_creds;

	/*
	 * If cache already contains this credential, remove it first.
	 */
	retval = krb5_cc_retrieve_cred(my_context->krb5_context,
				       my_context->target_ccache,
				       retrieve_flags,
				       &my_context->creds,
				       &found_creds);

	switch(retval) {
	case KRB5_FCC_NOFILE:
	    /* No cache */
	    if (my_context->verbose)
		printf("Target cache %s doesn't exist - will initialize\n",
		       my_context->target_cache_name);

	    my_context->initialize_cache = 1;
	    break;

	case KRB5_CC_NOTFOUND:
	    /* No match found */
	    break;

	case 0:
	    /* Match found */
	    krb5_free_cred_contents(my_context->krb5_context, &found_creds);

	    /*
	     * It would be nice to delete the existing cred here, but
	     * krb5_cc_remove_cred() is not implemented (for FILE at
	     * least).
	     */
	    com_err(my_context->progname, 0,
		    "Target cache %s already has matching credential.",
		       my_context->target_cache_name);

	    retval = -1;

	    goto cleanup;

	default:
	    /* Some other error */
	    com_err(my_context->progname, retval,
		    "Reading credentials cache %s",
		    my_context->target_cache_name);
	    goto cleanup;
	}
    }

    /* Initialize cache if requested */
    if (my_context->initialize_cache) {
	if (my_context->verbose)
	    printf("Initializing cache %s\n",
		   my_context->target_cache_name);
	
	if (retval = krb5_cc_initialize(my_context->krb5_context,
					my_context->target_ccache,
					my_context->target_cprinc)) {
	    com_err(my_context->progname, retval, "initializing cache");
	    goto cleanup;
	}
    }

    if (my_context->verbose)
	printf("Storing credentials to %s\n",
	       my_context->target_cache_name);

    if (retval = krb5_cc_store_cred(my_context->krb5_context,
				    my_context->target_ccache,
				    &my_context->creds)) {
	com_err(my_context->progname, retval, "storing credentials");
	goto cleanup;
    }

 cleanup:
    return retval;
}


/*
 * Should we initialize the target credentials cache?
 */
static krb5_boolean
should_initialize_target_cache(krb525_client_context *my_context)
{
    /*
     * Did user request one way or the other?
     */
    if (my_context->dont_initialize_cache)
	return 0;

    if (my_context->initialize_cache)
	return 1;

    /*
     * Else, return no
     */
    return 0;
}



/*
 * Should we chown the target credientials cache?
 */
static krb5_boolean
should_chown_target_cache(krb525_client_context *my_context)
{
    /*
     * Did the user request one way or another?
     */
    if (my_context->dont_chown_target_cache)
	return 0;

    if (my_context->chown_target_cache)
	return 1;

    /*
     * Else, return no
     */
    return 0;
}



/*
 * Is the given principal a TGT?
 */
static krb5_boolean
is_tgt(krb525_client_context *my_context,
       krb5_principal princ)
{
    krb5_data *component;

    component = krb5_princ_component(my_context->krb5_context, princ, 0);

    return (strcmp(KRB5_TGS_NAME, component->data) == 0);
}



#ifdef AFS_KRB5
/*
 * Should we run aklog?
 */
static krb5_boolean
should_run_aklog(krb525_client_context *my_context)
{
    /*
     * Did the user request one way or another?
     */
    if (my_context->dont_run_aklog)
	return 0;

    if (my_context->run_aklog)
	return 1;

    /*
     * Dont run aklog by default if we are root
     */
    if (geteuid() == 0) {
	if (my_context->verbose)
	    printf("Not running aklog becuase we're root\n");
	return 0;
    }

    /*
     * If the output cache is not the default cache, then
     * running aklog won't help since aklog only looks in the target
     * cache
     */
    if (strcmp(my_context->target_cache_name,
	       krb5_cc_default_name(my_context->krb5_context)) != 0) {
	if (my_context->verbose)
	    printf("Not running aklog because target cache != default cache\n");
	return 0;
    }

    /*
     * Check with appdefaults, if they say no then no
     */
    krb5_appdefault_boolean(my_context->krb5_context,
			    my_context->progname,
			    &my_context->default_realm,
			    "krb5_run_aklog", 0,
			    (int *) &my_context->run_aklog);

    if (!my_context->run_aklog)
	return 0;

    /*
     * Make sure the target ticket makes sense. It should be either
     * a ticket-granting ticket or an afs service ticket.
     */
    if (is_tgt(my_context, my_context->target_sprinc))
	return 1;

    if (is_afs_service(my_context, my_context->target_sprinc))
	return 1;

    /*
     * Else, return no
     */
    return 0;
}


/*
 * Is given principal an afs service principal?
 */
static krb5_boolean
is_afs_service(krb525_client_context *my_context,
       krb5_principal princ)
{
    krb5_data *component;

    component = krb5_princ_component(my_context->krb5_context, princ, 0);

    return (strcmp("afs", component->data) == 0);
}


/*
 * Run aklog
 */
static void
run_aklog(krb525_client_context *my_context)
{
    char			*aklog_path;
    struct stat			st;


    /* Determine aklog's path */
    krb5_appdefault_string(my_context->krb5_context,
			   my_context->progname,
			   &my_context->default_realm,
			   "krb5_aklog_path",
			   INSTALLPATH "bin/aklog",
			   &aklog_path);

    /*
     * Make sure it exists before we try to run it
     */
    if (stat(aklog_path, &st) == 0) {
	if (my_context->verbose)
	    printf("Running %s\n", aklog_path);

	system(aklog_path);
    } else {
	if (my_context->verbose)
	    printf("Can't run aklog: %s doesn't exist",
		   aklog_path);
    }	

    free(aklog_path);
}

#endif /* AFS_KRB5 */
