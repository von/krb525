/*
 * srv_conf.c
 *
 * Routines to process the krb525 configuration files and check on the
 * legality of requests.
 *
 * $Id: srv_conf.c,v 1.3 1997/09/17 16:58:04 vwelch Exp $
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <regexpr.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "srv_conf.h"
#include "parse_conf.h"
#include "server.h"

char srv_conf_error[255] = "No error";


#define BUFFER_SIZE	256


static pconf_entry *find_string_in_list(pconf_entry *,
					char *);
static pconf_entry *find_string_in_regex_list(pconf_entry *,
					      char *);
static pconf_entry *find_princ_in_regex_list(krb5_context,
					     pconf_entry *,
					     char *);
static char *find_string_in_regex_values(pconf_entry *,
					 char *);
static char *find_host_in_regex_values(pconf_entry *,
				       struct sockaddr_in *);
static char *find_princ_in_regex_values(krb5_context,
					pconf_entry *,
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
	return -1;
    }

    return 0;
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
 * Check request against configuration. Returns 0 if good, -1 otherwise
 */
int
check_conf(krb525_request *request,
	   krb5_ticket *ticket /* Not used */)
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
     * First check the list of allowed clients
     */
    entry = find_string_in_list(conf, "allowed_clients");

    if (entry == NULL) {
	sprintf(srv_conf_error, "No clients allowed!");
	goto done;
    }

    if (find_princ_in_regex_values(request->krb5_context,
				   entry, request->cname) == NULL) {
	sprintf(srv_conf_error, "Client not allowed");
	goto done;
    }

    /*
     * If this is a special client (it has it's own entry) then we check
     * things against that.
     */
    client_conf = find_princ_in_regex_list(request->krb5_context,
					   conf, request->cname);

    if (client_conf != NULL) {
	/*
	 * Client has it's own entry of the form:
	 *
	 * client = {
	 *   target_clients = <client1>, <client2>, <client3>, ... ;
	 *   target_servers = <server1>, <server2>, <client4>, ... ;
	 *   allowed_hosts = <host1>, <host2>, <host3>, ...;
	 * }
	 */

	/* Find the allowed hosts list and check this host */
	list = find_string_in_list(client_conf->list, "allowed_hosts");

	if (list == NULL) {
	    sprintf(srv_conf_error, "No hosts allowed for client");
	    goto done;
	}
    
	if (find_host_in_regex_values(list, &(request->addr)) == NULL) {
	    sprintf(srv_conf_error, "Host not allowed");
	    goto done;
	}
    
	/*
	 * If the client is changing, then check the target
	 */
    
	if (strcmp(request->cname, request->target_cname)) {

	    entry = find_string_in_list(client_conf->list, "target_clients");

	    if (entry == NULL) {
		sprintf(srv_conf_error, "No client changes allowed");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context, entry,
					   request->target_cname) == NULL) {
		sprintf(srv_conf_error, "Target client not allowed");
		goto done;
	    }
	}

	/*
	 * If the server is changing, then check the target
	 */
	if (strcmp(request->sname, request->target_sname)) {

	    entry = find_string_in_list(client_conf->list, "target_servers");

	    if (entry == NULL) {
		sprintf(srv_conf_error, "No server changes allowed");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context, entry,
					   request->target_sname) == NULL) {
		sprintf(srv_conf_error, "Target server not allowed");
		goto done;
	    }
	}

	/* Checks out OK */

    } else {
	/* No special entry for client, check for defaults */

	/* Find the allowed hosts list and check this host */
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
	 * If the client is changing, check the mapping
	 */
    
	if (strcmp(request->cname, request->target_cname)) {

	    list = find_string_in_list(conf, "client_mappings");

	    if (list == NULL) {
		sprintf(srv_conf_error, "No client mappings allowed");
		goto done;
	    }

	    entry = find_princ_in_regex_list(request->krb5_context, 
					     list->list, request->cname);

	    if (entry == NULL) {
		sprintf(srv_conf_error, "No mappings for client");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context, entry,
					   request->target_cname) == NULL) {
		sprintf(srv_conf_error, "Target client not a legal mapping");
		goto done;
	    }
	}

	/*
	 * If the server is changing, check the mapping
	 */
    
	if (strcmp(request->sname, request->target_sname)) {

	    list = find_string_in_list(conf, "server_mappings");

	    if (list == NULL) {
		sprintf(srv_conf_error, "No server mappings allowed");
		goto done;
	    }

	    entry = find_princ_in_regex_list(request->krb5_context,
				       list->list, request->sname);

	    if (entry == NULL) {
		sprintf(srv_conf_error, "No mappings for server");
		goto done;
	    }

	    if (find_princ_in_regex_values(request->krb5_context, entry,
					   request->target_sname) == NULL) {
		sprintf(srv_conf_error, "Target server not a legal mapping");
		goto done;
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
			 pconf_entry *entry,
			 char *pname)
{
    pconf_entry		*found_entry = NULL;
    char		*local_realm;
    char		*princ_realm;


    if (found_entry = find_string_in_regex_list(entry, pname))
	return found_entry;

    if (krb5_get_default_realm(kcontext, &local_realm))
	return NULL;	/* No good way to get an error out of here. */


    princ_realm = strchr(pname, '@');

    if (princ_realm && (strcmp(princ_realm + 1, local_realm) == 0)) {
	*princ_realm = '\0';

	found_entry = find_string_in_regex_list(entry, pname);

	*princ_realm = '@';
    }

    krb5_xfree(local_realm);

    return found_entry;
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
			   pconf_entry *entry,
			   char *pname)
{
    char		*found_string = NULL;
    char		*local_realm;
    char		*princ_realm;


    if (found_string = find_string_in_regex_values(entry, pname))
	return found_string;

    if (krb5_get_default_realm(kcontext, &local_realm))
	return NULL;	/* No good way to get an error out of here. */


    princ_realm = strchr(pname, '@');

    if (princ_realm && (strcmp(princ_realm + 1, local_realm) == 0)) {
	*princ_realm = '\0';

	found_string = find_string_in_regex_values(entry, pname);

	*princ_realm = '@';
    }

    krb5_xfree(local_realm);

    return found_string;
}

    

/*
 * Compare a string with a regular expression, returning 1 if they match,
 * 0 if they don't and -1 on error.
 */
static int
regex_compare(char *regex,
	      char *string)
{
    char 		*buf;
    char		*bufp;
    char		*expbuf;
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

    expbuf = compile(buf, NULL, NULL);

    free(buf);

    if (!expbuf) {
	sprintf(srv_conf_error, "Error parsing string \"%s\"",
		regex);
	return -1;
    }

    result = step(string, expbuf);

    free(expbuf);

    return result;
}
    
 
