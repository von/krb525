/*
 * parse_conf.c
 *
 * Routines to read and parse a configuration file.
 *
 * $Id: parse_conf.c,v 1.1 1997/09/08 15:41:33 vwelch Exp $
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "parse_conf.h"

#define BUFSIZE			256

#define DEFAULT_DELIM		" \n\t"


struct _pconf_context {
    FILE *file;
    char *filename;
    int linenum;
    char *delim;
};

typedef struct _pconf_context pconf_context;

char pconf_error[BUFSIZE] = "No error";

static char *get_token(pconf_context *);
static pconf_entry *parse_file(pconf_context *);
static pconf_entry *new_pconf_entry();

/*
 * Externally available routines
 */

/*
 * Given a configuration filename, parse the file returning a linked
 * list of conf_entrys. Returns NULL on error and sets pconf_error.
 */
pconf_entry *
parse_conf(char *filename, char *delim)
{
    pconf_context pcontext;
    char *string;
    pconf_entry *entry;

    pcontext.file = fopen(filename, "r");

    if (pcontext.file == NULL) {
	sprintf(pconf_error, "Couldn't open file %s: %s",
		filename, strerror(errno));
	return NULL;
    }

    pcontext.linenum = 0;
    pcontext.filename = filename;
    pcontext.delim = (delim ? delim : DEFAULT_DELIM);

    entry = parse_file(&pcontext);

    return entry;
}


/*
 * Given a linked list of pconf_enteries, free them all.
 */
void
free_pconf_enteries(pconf_entry *entry)
{
    while(entry) {
	pconf_entry *next = entry->next;

	if (entry->string)
	    free(entry->string);

	if (entry->value)
	    free(entry->value);

	if (entry->list)
	    free_pconf_enteries(entry->list);

	free(entry);

	entry = next;
    }
}


/*
 * Internal Routines
 */

/*
 * Parse a configuration file. This reoutine is recursive in that if it
 * descents to a sublist (e.g. "sublist = { <sublist> }") it calls itself
 * on the sublist.
 */
static pconf_entry *
parse_file(pconf_context *pcontext)
{
    pconf_entry *head, *current;
    char *string;

    head = new_pconf_entry();

    if (head == NULL)
	return NULL;

    current = head;

    while (string = get_token(pcontext)) {
	if (strcmp(string, "}") == 0)		/* END of list */
	    return head;

	if (strcmp(string, "=") == 0) {
	    if ((current->string == NULL) ||
		(current->type != CONF_TYPE_NONE) ||
		((string = get_token(pcontext)) == NULL))
		{
		    sprintf(pconf_error, "Parse error on line %d of file %s",
			pcontext->linenum, pcontext->filename);
		    goto error_return;
		    
		}

	    if (strcmp(string, "{") == 0) {
		current->type = CONF_TYPE_LIST;
		current->list = parse_file(pcontext);
		if (current->list == NULL)
		    goto error_return;
	    } else {
		current->value = strdup(string);
		current->type = CONF_TYPE_VALUE;
	    }
	    
	    continue;
	}

	if (current->string) {
	    current->next = new_pconf_entry();
	    current = current->next;

	    if (current == NULL)
		goto error_return;
	}

	current->string = strdup(string);
    }

    return head;

error_return:
    /* Clean up all of our allocations and return NULL */
    free_pconf_enteries(head);
    return NULL;
}


/*
 * Get the next token from the currently being parsed file. Handles
 * getting new lines.
 */
static char *
get_token(pconf_context *pcontext)
{
    static char buffer[BUFSIZE];
    char *token = NULL;

    token = strtok(NULL, pcontext->delim);

    while (token == NULL) {
	if (fgets(buffer, BUFSIZE, pcontext->file) == NULL)
	    return NULL;

	if (buffer[strlen(buffer) - 1] == '\n')
	    (pcontext->linenum)++;

	token = strtok(buffer, pcontext->delim);
    }

    return token;
}


/*
 * Allocate and initialize and new pconf_entry structure.
 */
static pconf_entry *
new_pconf_entry()
{
    pconf_entry *entry;

    entry = (pconf_entry *) malloc(sizeof(*entry));

    if (entry == NULL) {
	sprintf(pconf_error, "malloc() failed");
	return NULL;
    }

    entry->string = NULL;
    entry->type = CONF_TYPE_NONE;
    entry->value = NULL;
    entry->list = NULL;
    entry->next = NULL;

    return entry;
}

