/*
 * srv_conf.c
 *
 * Routines to process the krb525 configuration files and check on the
 * legality of requests.
 *
 * $Id: srv_conf.c,v 1.2 1997/09/15 15:37:46 vwelch Exp $
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <regexpr.h>
 
#include "srv_conf.h"
#include "parse_conf.h"

char srv_conf_error[255] = "No error";


#define BUFFER_SIZE	256


static pconf_entry *find_entry_in_conf(pconf_entry *,
				       char *,
				       char *);

static pconf_entry *find_entry_in_list(pconf_entry *,
				       char *);

static int regex_compare(char *,
			 char *);




int check_conf(char *conf_file,
	       char *client_name,
	       char *target_name,
	       char *client_host)
{
    pconf_entry		*conf;
    int			retval = -1;


    if ((conf = parse_conf(conf_file, NULL)) == NULL) {
	strcpy(srv_conf_error, pconf_error);
	return -1;
    }

    if (find_entry_in_conf(conf, "allowed_clients", client_name) == NULL) {
	sprintf(srv_conf_error, "Client %s not allowed", client_name);
	goto done;
    }

    if (find_entry_in_conf(conf, "allowed_targets", target_name) == NULL) {
	sprintf(srv_conf_error, "Target %s not allowed", target_name);
	goto done;
    }

    if (find_entry_in_conf(conf, "allowed_hosts", client_host) == NULL) {
	sprintf(srv_conf_error, "Client host %s not allowed", client_host);
	goto done;
    }

    /* Checks out OK */
    retval = 0;

done:
    free_pconf_enteries(conf);
    return retval;
}



static pconf_entry *
find_entry_in_conf(pconf_entry *conf,
		   char *list_name,
		   char *entry_name)
{
    pconf_entry		*list;


    if ((list = find_entry_in_list(conf, list_name)) == NULL)
	return NULL;

    return find_entry_in_list(list->list, entry_name);
}



static pconf_entry *
find_entry_in_list(pconf_entry *list,
		   char *entry)
{
    while(list != NULL) {
	if (list->string) {
	    int retval;

	    retval = regex_compare(list->string, entry);

	    if (retval == 1)
		return list;

	    if (retval == -1)
		return NULL;
	}

	list = list->next;
    }

    return NULL;
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
    
 
