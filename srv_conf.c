/*
 * srv_conf.c
 *
 * Routines to process the krb525 configuration files and check on the
 * legality of requests.
 *
 * $Id: srv_conf.c,v 1.7 1999/10/08 21:37:58 vwelch Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#if defined(HAVE_REGCOMP) && defined(HAVE_REGEX_H)
#include <regex.h>

#elif defined(HAVE_COMPILE) && defined(HAVE_REGEXPR_H)
#include <regexpr.h>

#else
#define NO_REGEX_SUPPORT

#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "srv_conf.h"
#include "parse_conf.h"
#include "server.h"
#include "version.h"

char srv_conf_error[255] = "No error";


#define BUFFER_SIZE	256


static int check_conf_version();
static char *get_first_value(pconf_entry *);
static pconf_entry *find_string_in_list(pconf_entry *,
					char *);
static pconf_entry *find_string_in_regex_list(pconf_entry *,
					      char *);
static pconf_entry *find_princ_in_regex_list(krb5_context,
					     krb5_principal,
					     pconf_entry *);
static char *find_string_in_regex_values(pconf_entry *,
					 char *);
static char *find_host_in_regex_values(pconf_entry *,
				       struct sockaddr_in *);
static char *find_princ_in_regex_values(krb5_context,
					krb5_principal,
					pconf_entry *);
static int conf_string_matches_princ(krb5_context,
				     krb5_principal,
				     char *);
static int regex_compare(char *,
			 char *);


/*
 * Our local storage
 */
static pconf_entry	*conf = NULL;



/*
 * Initialize our configuration. Return -1 on error, 0 otherwise.
 */
int
init_conf(char *conf_file)
{

    if ((conf = parse_conf(conf_file, NULL)) == NULL) {
	strcpy(srv_conf_error, pconf_error);
	goto error;
    }

    if (check_conf_version())
	goto error;

    return 0;

 error:
    if (conf) {
	free_pconf_enteries(conf);
	conf = NULL;
    }

    return -1;
}


/*
 * Free any storage we had
 */
void
free_conf()
{
    free_pconf_enteries(conf);
    conf = NULL;
}



/*
 * Check the configuration file version number and see if it's
 * OK. Returns 0 if ok, -1 otherwise.
 */
static int
check_conf_version()
{
    pconf_entry		*entry;

    char		*conf_version_string;
    int			conf_version_major;
    int			conf_version_minor;
    int			conf_version_patchlevel;

    int			my_version_major;
    int			my_version_minor;
    int			my_version_patchlevel;

    int			conf_newer = 0;


    /* Check version string of configuration file */
    entry = find_string_in_list(conf, "version");

    conf_version_string = get_first_value(entry);

    if (conf_version_string == NULL) {
	sprintf(srv_conf_error, "No version number in configuration file");
	return -1;
    }

    /* Parse configuration file version */
    if (sscanf(conf_version_string,
	       "%d.%d.%d",
	       &conf_version_major,
	       &conf_version_minor,
	       &conf_version_patchlevel) != 3) {
	sprintf(srv_conf_error,
		"Error parsing configuration file version string");
	return -1;
    }

    /* Parse our version number */
    if (sscanf(KRB525_VERSION_STRING,
	       "%d.%d.%d",
	       &my_version_major,
	       &my_version_minor,
	       &my_version_patchlevel) != 3) {
	sprintf(srv_conf_error,
		"Error parsing my version string (shouldn't happen)");
	return -1;
    }

    /* Make sure file is not newer than me */
    if (conf_version_major > my_version_major)
	conf_newer = 1;

    if ((conf_version_major == my_version_major) &&
	(conf_version_minor > my_version_minor))
	conf_newer = 1;

    /* Patchlevel should not make a difference */

    if (conf_newer) {
	sprintf(srv_conf_error,
		"Configuration file version number is newer than mine");
	return -1;
    }

    /* Checks for too old of a file could eventually go here */
    return 0;
}



/*
 * Check request against configuration. Returns 0 if good, -1 otherwise
 */
int
check_conf(krb525_request *request)
{
    pconf_entry		*entry;
    pconf_entry		*client_conf;
    pconf_entry		*list;
    int			retval = -1;


    /*
     * Check to be sure we're initialized
     */
    if (conf == NULL) {
	sprintf(srv_conf_error, "Configuration not initialized");
	return -1;
    }

    /*
     * RULE 1: Make sure requesting client is on allowed_clients list
     */
    entry = find_string_in_list(conf, "allowed_clients");

    if (entry == NULL) {
	sprintf(srv_conf_error, "No clients allowed!");
	goto done;
    }

    if (find_princ_in_regex_values(request->krb5_context,
				   request->client,
				   entry) == NULL) {
	sprintf(srv_conf_error, "Client not allowed");
	goto done;
    }

    /*
     * RULE 2: Make sure client isn't on disallowed_clients list, if
     *         it exists.
     */
    entry = find_string_in_list(conf, "disallowed_clients");

    if (entry) {
	if (find_princ_in_regex_values(request->krb5_context,
				       request->client,
				       entry) != NULL) {
	    sprintf(srv_conf_error, "Client explicitily disallowed");
	    goto done;
	}
    }

    /* See if requesting client has an individual list */
    client_conf = find_princ_in_regex_list(request->krb5_context,
					   request->client,
					   conf);

    if (client_conf != NULL) {
	/*
	 * Requesting client has it's own entry of the form:
	 *
	 * client = {
	 *   target_clients = <client1>, <client2>, <client3>, ... ;
	 *   target_servers = <server1>, <server2>, <client4>, ... ;
	 *   allowed_hosts = <host1>, <host2>, <host3>, ...;
	 * }
	 */

	/*
	 * RULE 3: If the requesting client has a individual list, use that list
	 *	   in preference to the default lists for all further checks
	 */

	/*
         * RULE 3a: If the requesting client has it's own allowed_hosts
         *          list make sure host is on the client's allowed_hosts
         *          list otherwise make sure the client is on the default
         *          allowed_hosts list.
         */
	list = find_string_in_list(client_conf->list, "allowed_hosts");

	if (list == NULL) {
	    /* Get default allowed_hosts list */
	    list = find_string_in_list(conf, "allowed_hosts");
	}

	if (list == NULL) {
	    sprintf(srv_conf_error, "No hosts allowed for client");
	    goto done;
	}
    
	if (find_host_in_regex_values(list, &(request->addr)) == NULL) {
	    sprintf(srv_conf_error, "Host not allowed");
	    goto done;
	}

    	/*
	 * Rule 3b: If the requesting client has it's own
	 *          disallowed_hosts list make sure host is not on the
	 *          client's disallowed_hosts list, otherwise make sure
	 *          the host is not on the default disallowed_hosts list,
	 *          if it exists.
	 */
	entry = find_string_in_list(client_conf->list, "disallowed_hosts");

	if (entry == NULL) {
	    /* Get default disallowed_hosts list */
	    entry = find_string_in_list(conf, "disallowed_hosts");
	}

	if (entry) {
	    if (find_host_in_regex_values(entry, &(request->addr)) != NULL) {
		sprintf(srv_conf_error, "Host explicitily disallowed");
		goto done;
	    }
	}

	if (!krb5_principal_compare(request->krb5_context,
				    request->client,
				    request->tkt_client)) {
	    /*
	     * Rule 3c: If the requesting client is different than the
	     *          ticket client, the ticket client must appear
	     *          in the source_clients list
	     */
	    entry = find_string_in_list(client_conf->list, "source_clients");
	    
	    if (entry == NULL) {
		sprintf(srv_conf_error, "Client on ticket must match requestor");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context,
					   request->tkt_client,
					   entry) == NULL) {
		sprintf(srv_conf_error, "Source client not allowed");
		goto done;
	    }

	    /*
	     * Rule 3d: If the requesting client is different than the
	     *          ticket client, the ticket client must not appear
	     *          on the disallowed_source_clients list, if it
	     *          exists.
	     */
	    entry = find_string_in_list(client_conf->list,
					"disallowed_source_clients");

	    if (entry) {
		if (find_princ_in_regex_values(request->krb5_context,
					       request->tkt_client,
					       entry) != NULL) {
		    sprintf(srv_conf_error,
			    "Source client explicitly disallowed");
		    goto done;
		}
	    }
	}

	if (!krb5_principal_compare(request->krb5_context,
				    request->tkt_client,
				    request->target_client)) {

	    /*
	     * Rule 3e: If client is changing, make sure the target client is
	     *          on the client's target_clients list
	     */
   
	    entry = find_string_in_list(client_conf->list, "target_clients");

	    if (entry == NULL) {
		sprintf(srv_conf_error, "No client changes allowed");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context,
					   request->target_client,
					   entry) == NULL) {
		sprintf(srv_conf_error, "Target client not allowed");
		goto done;
	    }

	    /*
	     * Rule 3f: If client is changing, make sure the target client is
	     *          not on the client's disallowed_target_clients list,
	     *	        if it exists.
	     */
	    entry = find_string_in_list(client_conf->list,
					"disallowed_target_clients");

	    if (entry) {
		if (find_princ_in_regex_values(request->krb5_context,
					       request->target_client,
					       entry) != NULL) {
		    sprintf(srv_conf_error,
			    "Target client explicitily disallowed");
		    goto done;
		}
	    }
	}

	if (!krb5_principal_compare(request->krb5_context,
				    request->tkt_server,
				    request->target_server)) {

	    /*
	     * Rule 3g: If the server is changing, make sure the target
	     *          server is on the client's target_servers list.
	     */
	    entry = find_string_in_list(client_conf->list, "target_servers");

	    if (entry == NULL) {
		sprintf(srv_conf_error, "No server changes allowed");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context,
					   request->target_client,
					   entry) == NULL) {
		sprintf(srv_conf_error, "Target server not allowed");
		goto done;
	    }

	    /*
	     * Rule 3h: If the server is changing, make sure the target
	     *          server is not on the client's
	     *          disallowed_target_servers list, if it exists.
	     */
	    entry = find_string_in_list(client_conf->list,
					"disallowed_target_servers");

	    if (entry) {
		if (find_princ_in_regex_values(request->krb5_context,
					       request->target_server,
					       entry) != NULL) {
		    sprintf(srv_conf_error,
			    "Target service explicitily disallowed");
		    goto done;
		}
	    }
	}

	/* Checks out OK */

    } else {

	/*
	 * Rule 4: If the client had no individual entry use the default
	 *         lists.
	 */

	/*
	 * Rule 4a: Make sure the requesting client matches the client
	 *          on the ticket.
	 */
	if (!krb5_principal_compare(request->krb5_context,
				    request->client,
				    request->tkt_client)) {
	    sprintf(srv_conf_error,
		    "Requesting client doesn't match client on ticket");
	    goto done;
	}

	/*
	 * Rule 4b: Make sure the host is on the default allowed_hosts list
	 */
	list = find_string_in_list(conf, "allowed_hosts");

	if (list == NULL) {
	    sprintf(srv_conf_error, "No default hosts allowed");
	    goto done;
	}
    
	if (find_host_in_regex_values(list, &(request->addr)) == NULL) {
	    sprintf(srv_conf_error, "Host not allowed in default list");
	    goto done;
	}

	/*
	 * Rule 4c: Make sure the host is not on the default disallowed_hosts
	 *          list, if it exists.
	 */
	entry = find_string_in_list(conf, "disallowed_hosts");

	if (entry) {
	    if (find_host_in_regex_values(entry, &(request->addr)) != NULL) {
		sprintf(srv_conf_error, "Host explicitily disallowed");
		goto done;
	    }
	}

	if (!krb5_principal_compare(request->krb5_context,
				    request->tkt_client,
				    request->target_client)) {

	    /*
	     * Rule 4d: If the client is changing make sure the source
	     *          and target mapping appear in the client_mappings
	     *          list.
	     */
	    list = find_string_in_list(conf, "client_mappings");

	    if (list == NULL) {
		sprintf(srv_conf_error, "No client mappings allowed");
		goto done;
	    }

	    entry = find_princ_in_regex_list(request->krb5_context, 
					     request->tkt_client,
					     list->list);

	    if (entry == NULL) {
		sprintf(srv_conf_error, "No mappings for client");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context,
					   request->target_client,
					   entry) == NULL) {
		sprintf(srv_conf_error, "Target client not a legal mapping");
		goto done;
	    }

	    /*
	     * Rule 4e: If the client is changing make sure the target
	     *	        client does not appear in the
	     *          disallowed_target_clients list, if it exists.
	     */
	    entry = find_string_in_list(conf,
					"disallowed_target_clients");

	    if (entry) {
		if (find_princ_in_regex_values(request->krb5_context,
					       request->target_client,
					       entry) != NULL) {
		    sprintf(srv_conf_error,
			    "Target client explicitily disallowed");
		    goto done;
		}
	    }
	}

	if (!krb5_principal_compare(request->krb5_context,
				    request->tkt_server,
				    request->target_server)) {

	    /*
	     * Rule 4f: If the server is changing, make sure the source
	     *          and target server mapping appear in the
	     *          server_mappings list.
	     */
	    list = find_string_in_list(conf, "server_mappings");

	    if (list == NULL) {
		sprintf(srv_conf_error, "No server mappings allowed");
		goto done;
	    }

	    entry = find_princ_in_regex_list(request->krb5_context,
					     request->target_server,
					     list->list);

	    if (entry == NULL) {
		sprintf(srv_conf_error, "No mappings for server");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context,
					   request->target_server,
					   entry) == NULL) {
		sprintf(srv_conf_error, "Target server not a legal mapping");
		goto done;
	    }

	    /*
	     * Rule 4g: If the server is changing make sure the target
	     *          server does not appear in the
	     *          disallowed_target_servers list, if it exists.
	     */
	    entry = find_string_in_list(conf, "disallowed_target_servers");

	    if (entry) {
		if (find_princ_in_regex_values(request->krb5_context,
					       request->target_server,
					       entry) != NULL) {
		    sprintf(srv_conf_error, "Target service explicitily disallowed");
		    goto done;
		}
	    }
	}

	/* Checks out OK */
    }

    /*
     * If we've gotten here, then we passed all the tests
     */
    retval = 0;

done:
    return retval;
}




/*
 * Return the first string in an entry
 */
static char *
get_first_value(pconf_entry *entry)
{
    if (!entry || !entry->values)
	return NULL;

    return *(entry->values);
}



/*
 * Find string in list and return entry
 */
static pconf_entry *
find_string_in_list(pconf_entry *entry,
		    char *string)
{
    while(entry) {
	char **str = entry->strings;

	while(*str) {
	    if (strcmp(string, *str) == 0)
		return entry;

	    str++;
	}

	entry = entry->next;
    }

    return NULL;
}




/*
 * Find string in list of regexs and return entry
 */
static pconf_entry *
find_string_in_regex_list(pconf_entry *entry,
			  char *string)
{
    while(entry) {
	char **str = entry->strings;

	while(*str) {
	    if (regex_compare(*str, string))
		return entry;

	    str++;
	}

	entry = entry->next;
    }

    return NULL;
}



/*
 * Find a principal in a regex list. First try the name as given,
 * then if it's in the default realm, try without the realm.
 */
static pconf_entry *
find_princ_in_regex_list(krb5_context kcontext,
			 krb5_principal princ,
			 pconf_entry *entry)
{
    while(entry) {
	char **str = entry->strings;

	while(*str) {
	    if (conf_string_matches_princ(kcontext,
					  princ,
					  *str))
		return entry;

	    str++;
	}
	
	entry = entry->next;
    }

    return NULL;
}



/*
 * Seach through the list of values in entry (which are assumed to be
 * regexs). If string is found to match one, return a pointer to the one
 * it matches, otherwise return NULL.
 */
static char *
find_string_in_regex_values(pconf_entry *entry,
			    char *string)
{
    char		**value = entry->values;


    while(*value) {
	if (regex_compare(*value, string))
	    return *value;

	value++;
    }
    
    return NULL;
}


/*
 * Given a host address, look for it in the values list (which is assumed
 * to be made up of regexs) both by it dot address (e.g. 10.11.12.13) and
 * by full hostname.
 */
static char *
find_host_in_regex_values(pconf_entry *entry,
			  struct sockaddr_in *sockaddr)
{
    char		**value = entry->values;
    char		*dot_addr;
    char		*hostname = NULL;
    struct hostent	*hinfo;


    dot_addr = inet_ntoa(sockaddr->sin_addr);

    hinfo = gethostbyaddr((char *) &(sockaddr->sin_addr.s_addr),
			  sizeof(sockaddr->sin_addr.s_addr),
			  sockaddr->sin_family);
    
    if (hinfo)
	hostname = hinfo->h_name;

    while (*value) {
	if (dot_addr && regex_compare(*value, dot_addr))
	    return *value;

	if (hostname && regex_compare(*value, hostname))
	    return *value;

	value++;
    }

    return NULL;
}



/*
 * Find a principal in a regex values list. First try the name as given,
 * then if it's in the default realm, try without the realm.
 */
static char *
find_princ_in_regex_values(krb5_context kcontext,
			   krb5_principal princ,
			   pconf_entry *entry)
{
    char		**value = entry->values;

    while (*value) {
	if (conf_string_matches_princ(kcontext, princ, *value))
	    return *value;

	value++;
    }

    return NULL;
}

    

/*
 * Is the given principal matched by the given string from the conf file
 * 1 == yes, 0 == no or error
 */
static int
conf_string_matches_princ(krb5_context context,
			  krb5_principal princ,
			  char *conf_string)
{
    krb5_error_code		retval;
    krb5_principal		conf_princ;
    int				component;
    int				result = 0;


    /* Parse the configuration string */
    retval = krb5_parse_name(context, conf_string, &conf_princ);

    if (retval) {
	/* No good way to get out an error */
	return 0;
    }

    /* Do they match outright? If so shortcut out of here */
    if (krb5_principal_compare(context, princ, conf_princ)) {
	result = 1;
	goto done;
    }

    /* A realm of '*' in the configuration file matches any realm */
    if (strcmp(krb5_princ_realm(context, conf_princ)->data, "*") != 0) {
	/* Check and make sure realms match */
	if (!krb5_realm_compare(context, princ, conf_princ))
	    goto done;
    }

    /* Now make sure they have the same number of components */
    if (krb5_princ_size(context, princ) != krb5_princ_size(context, conf_princ))
	goto done;

    /* Now check each component */
    for (component = 0;
	 component < krb5_princ_size(context, princ) ;
	 component ++) {
	/*
	 * A component of '*' in configuration file which matches any
	 * anything in that component
	 */
	if (strcmp(krb5_princ_component(context, conf_princ, component)->data,
		   "*") == 0)
	    continue;

	/*
	 * otherwise make sure components match
	 */
	if (strcmp(krb5_princ_component(context, conf_princ, component)->data,
		   krb5_princ_component(context, princ, component)->data) != 0)
	    goto done;
    }

    /* Match */
    result = 1;

 done:
    krb5_free_principal(context, conf_princ);

    return result;
}
/*
 * Compare a string with a regular expression, returning 1 if they match,
 * 0 if they don't and -1 on error.
 */
static int
regex_compare(char *regex,
	      char *string)
{
#ifndef NO_REGEX_SUPPORT
    char 		*buf;
    char		*bufp;
    int			result;



    /*
     * First we convert the regular expression from the human-readable
     * form (e.g. *.domain.com) to the machine-readable form
     * (e.g. ^.*\.domain\.com$).
     *
     * Make a buffer large enough to hold the largest possible converted
     * regex from the string plus our extra characters (one at the
     * begining, one at the end, plus a NULL).
     */
    buf = (char *) malloc(2 * strlen(regex) + 3);

    if (!buf) {
	sprintf(srv_conf_error, "malloc() failed");
	return -1;
    }

    bufp = buf;
    *bufp++ = '^';

    while (*regex) {
	switch(*regex) {

	case '*':
	    /* '*' turns into '.*' */
	    *bufp++ = '.';
	    *bufp++ = '*';
	    break;

	case '?':
	    /* '?' turns into '.' */
	    *bufp++ = '.';
	    break;

	    /* '.' needs to be escaped to '\.' */
	case '.':
	    *bufp++ = '\\';
	    *bufp++ = '.';
	    break;

	default:
	    *bufp++ = *regex;
	}

	regex++;
    }

    *bufp++ = '$';
    *bufp++ = '\0';

#ifdef HAVE_REGCOMP
    {
	regex_t preg;

	if (regcomp(&preg, buf, REG_EXTENDED)) {
	    sprintf(srv_conf_error, "Error parsing string \"%s\"",
		    regex);
	    result = -1;

	} else {
	    result = (regexec(&preg, string, 0, NULL, 0) == 0);
	    regfree(&preg);
	}
    }

#elif HAVE_COMPILE
    {
	char *expbuf;

	expbuf = compile(buf, NULL, NULL);

	if (!expbuf) {
	    sprintf(srv_conf_error, "Error parsing string \"%s\"",
		    regex);
	    result = -1;

	} else {
	    result = step(string, expbuf);
	    free(expbuf);
	}
    }
#else

    /*
     * If we've gotten here then there is an error in the configuration
     * process or this file's #ifdefs
     */
    error -  No regular expression support found.

#endif

    if (buf)
	free(buf);

    return result;

#else /* NOREGEX_SUPPORT */

    /* No regular expression support */
    return (strcmp(regex, string) == 0);

#endif /* NO_REGEX_SUPPORT */
}
    
 
