/*
 * srv_conf.c
 *
 * Routines to process the krb525 configuration files and check on the
 * legality of requests.
 *
 * $Id: srv_conf.c,v 1.1 1997/09/08 15:41:33 vwelch Exp $
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
 
#include "srv_conf.h"
#include "parse_conf.h"

char srv_conf_error[255] = "No error";


#define BUFFER_SIZE	256


static pconf_entry *find_entry_in_conf(pconf_entry *,
				       char *,
				       char *);

static pconf_entry *find_entry_in_list(pconf_entry *,
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
	if (list->string && (strcmp(list->string, entry) == 0))
	    return list;

	list = list->next;
    }

    return NULL;
}

