/*
 * krb525_check_conf.c
 *
 * Check the krb525d configuration.
 *
 * $Id: krb525_check_conf.c,v 1.2 1999/10/08 19:49:25 vwelch Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/types.h>

#include "krb5.h"

#include "server.h"
#include "srv_conf.h"
#include "version.h"

#define DEFAULT_CONF_FILE	"./krb525.conf"

#define error_exit()	{ exit_code = 2; goto cleanup; }

int
main(argc, argv)
     int argc;
     char *argv[];
{
    krb5_context context;
    krb5_error_code retval;

    krb5_data default_realm;

    char *requesting_cname = NULL;
    char *cname = NULL;
    char *target_cname = NULL;
    char *sname = NULL;
    char *target_sname = NULL;

    krb525_request request;

    char *request_host = NULL;
    char request_host_buffer[256];
    struct hostent *hinfo = NULL;

    char *source_cache_name = NULL;
    krb5_ccache source_ccache = NULL;

    char *conf_file = DEFAULT_CONF_FILE;

    extern int opterr, optind;
    extern char * optarg;
    int ch;

    char *progname;

    int verbose = 0;

    int exit_code = 0;



    /* Get our name, removing preceding path */
    if (progname = strrchr(argv[0], '/'))
	progname++;
    else
	progname = argv[0];

    /*
     * Initialize request structure
     */
    request.krb5_context = NULL;
    request.ticket = NULL;
    request.target_client = NULL;
    request.target_server = NULL;

    
    opterr = 0;

    while ((ch = getopt(argc, argv, "c:C:h:i:r:s:S:vV")) != EOF)
	switch (ch) {
	case 'c':
	    cname = strdup(optarg);
	    break;

	case 'C':
	    target_cname = strdup(optarg);
	    break;
	    
	case 'h':
	    request_host = optarg;
	    break;

	case 'i':
	    source_cache_name = optarg;
	    break;

	case 'r':
	    requesting_cname = strdup(optarg);
	    break;
		
	case 's':
	    sname = strdup(optarg);
	    break;

	case 'S':
	    target_sname = strdup(optarg);
	    break;

	case 'v':
	    verbose = 1;
	    break;

	case 'V':
	    printf("%s Version %s\n", progname, KRB525_VERSION_STRING);
	    exit(0);

	default:
	    opterr = 1;
	    break;
	}

        
    if ((argc - optind) != 0)
	conf_file = argv[optind++];

    if ((argc - optind) != 0)
	fprintf(stderr,
		"%s: Ignoring extra command line options starting with %s\n",
		progname, argv[optind]);

    if (opterr) {
	fprintf(stderr, "Usage: %s [<options>]\n"
		"Options are:\n"
		"   -c <client name>         Client for credentials to convert\n"
		"   -C <target client>       Client to convert to\n"
		"   -h <hostname>            Check as if request came from given host"
		"   -i <input cache>         Specify cache to get credentials from\n"
		"   -r <client name>         Client who made the request\n"
		"   -s <service name>        Service for credentials to convert\n"
		"   -S <target service>      Service to convert to\n"

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


    /*
     * Get our default realm
     */
    if (retval = krb5_get_default_realm(context, &(default_realm.data))) {
	com_err(progname, retval, "resolving default realm");
	error_exit();
    }

    default_realm.length = strlen(default_realm.data);

    /*
     * Deal with the client name and principal
     */
    if (cname) {
	/* Parse the given client name */
	if (verbose)
	    printf("Parsing client name %s\n", cname);

	if (retval = krb5_parse_name(context, cname,
				     &(request.tkt_client))) {
	    com_err (progname, retval, "when parsing client name");
	    error_exit();
	}

	free(cname);
	cname = NULL;

    } else {
	/* No client name given, use default from cache */
	if (verbose)
	    printf("Getting client name from credentials cache");

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

	if (retval = krb5_cc_get_principal(context, source_ccache,
					   &(request.tkt_client))) {
	    com_err(progname, retval, "while getting principal from cache");
	    error_exit();
	}
    }

    if (retval = krb5_unparse_name(context,
				   request.tkt_client,
				   &cname)) {
	com_err(progname, retval, "when unparsing client name from cache");
	error_exit();
    }

    if (verbose)
	printf("Client name is %s\n", cname);

    /*
     * Dealing with requesting client name
     */
    if (!requesting_cname)
	requesting_cname = strdup(cname);

    if (verbose)
	printf("Parsing requesting client name %s\n", requesting_cname);

    if (retval = krb5_parse_name(context, requesting_cname,
				 &(request.client))) {
	com_err (progname, retval, "when parsing requesting client name");
	error_exit();
    }

    free(requesting_cname);
    requesting_cname = NULL;

    if (retval = krb5_unparse_name(context,
				   request.client,
				   &requesting_cname)) {
	com_err(progname, retval,
		"when unparsing requestingclient name from cache");
	error_exit();
    }

    if (verbose)
	printf("Requesting client name is %s\n", requesting_cname);


    /*
     * Deal with the service name and principal
     */
    if (sname) {
	/* Parse the given service name */
	if (verbose)
	    printf("Parsing service name %s\n", sname);

	if (retval = krb5_parse_name(context, sname,
				     &(request.tkt_server))) {
	    com_err(progname, retval, "parsing service name");
	    error_exit();
	}

	free(sname);
	sname = NULL;

    } else {
	/* No service name given, use krbtgt/<realm>@<realm */
	if (verbose)
	    printf("Building default server principal %s/%s@%s\n",
		   KRB5_TGS_NAME, default_realm.data, default_realm.data);

	if (retval = krb5_build_principal(context,
					  &(request.tkt_server),
					  default_realm.length,
					  default_realm.data,
					  KRB5_TGS_NAME,
					  default_realm.data,
					  0)) {
	    com_err (progname, retval,
		     "building default service principal");
	    error_exit();
	}
    }

    if (retval = krb5_unparse_name(context, request.tkt_server,
				   &sname)) {
	com_err (progname, retval, "when unparsing service");
	error_exit();
    }

    /*
     * If neither a target client name or target service name was
     * given, then target ticket is for current username
     */
    if (!target_cname && !target_sname) {
	struct passwd *pwd = NULL;

	if (verbose)
	    printf("No target client or server specified - getting ticket for"
		   " current username\n");

	pwd = getpwuid(geteuid());

	if (!pwd) {
	    perror("Password entry lookup failed");
	    error_exit();
	}

	target_cname = strdup(pwd->pw_name);

	/* free(pwd); */	/* Causes segfault */
    }

    /*
     * Deal with target client name
     */

    /* If no target client name given, use original client name */
    if (!target_cname) {
	if (verbose)
	    printf("No target client speicied, using original: %s\n",
		   cname);

	target_cname = strdup(cname);
    }

    if (retval = krb5_parse_name (context, target_cname,
				  &request.target_client)) {
	com_err (progname, retval, "when parsing name %s",
		 target_cname);
	error_exit();
    }

    free(target_cname);
    target_cname = NULL;

    if (retval = krb5_unparse_name(context, request.target_client,
				   &target_cname)) {
	com_err (progname, retval, "when unparsing client");
	error_exit();
    }

    /*
     * Deal with target server name
     */

    /* If no target server name given, use original server name */
    if (!target_sname) {
	if (verbose)
	    printf("No target server specified, using original: %s\n",
		   sname);
	target_sname = strdup(sname);
    }

    if (retval = krb5_parse_name (context, target_sname,
				  &(request.target_server))) {
	com_err (progname, retval, "when parsing name %s",
		 target_sname);
	error_exit();
    }

    free(target_sname);
    target_sname = NULL;

    if (retval = krb5_unparse_name(context, request.target_server,
				   &target_sname)) {
	com_err (progname, retval, "when unparsing server");
	error_exit();
    }

    /*
     * Deal with source hostname
     */
    if (request_host == NULL) {
	if (gethostname(request_host_buffer, sizeof(request_host_buffer))) {
	    perror("gethostname()");
	    error_exit();
	}
	request_host = request_host_buffer;
    }

    hinfo = gethostbyname(request_host);

    if (!hinfo) {
	fprintf(stderr, "%s: can't resolve hostname \"%s\"\n",
		progname, request_host);
	error_exit();
    }

    /* clear out the structure first */
    (void) memset((char *)&(request.addr), 0, sizeof(request.addr));

    request.addr.sin_family = hinfo->h_addrtype;
    memcpy((char *) &(request.addr.sin_addr),
	   (char *) hinfo->h_addr,
	   sizeof(request.addr.sin_addr));

    /*
     * Initialize configuration
     */
    if (verbose)
	printf("Reading configuration from %s\n", conf_file);

    retval = init_conf(conf_file);

    if (retval) {
	fprintf(stderr, "Error parsing configuration file: %s\n",
		srv_conf_error);
	error_exit();
    }

    /* 
     * Do it
     */

    if (verbose)
	printf("Checking configuration for:\n"
	       "      %s requesting:\n"
	       "    %s for %s\n"
	       "      converting to\n"
	       "    %s for %s\n"
	       "      from %s\n",
	       requesting_cname,
	       cname,
	       sname,
	       target_cname,
	       target_sname,
	       hinfo->h_name);

    retval = check_conf(&request);

    if (retval == 0) {
	printf("SUCCESS\n");
	exit_code = 0;

    } else {
	printf("FAILED: %s\n", srv_conf_error);
	exit_code = 1;
    }

 cleanup:
    if (cname) free(cname);
    if (sname) free(sname);
    if (target_cname) free(target_cname);
    if (target_sname) free(target_sname);
    if (requesting_cname) free(requesting_cname);

    exit(exit_code);
}

    
