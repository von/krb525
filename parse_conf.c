/*
 * parse_conf.c
 *
 * Routines to read and parse a configuration file.
 *
 * $Id: parse_conf.c,v 1.2 1997/09/17 16:57:59 vwelch Exp $
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
    int buffer_read;
    int whole_line;
};

typedef struct _pconf_context pconf_context;

char pconf_error[BUFSIZE] = "No error";

static pconf_entry *new_pconf_entry();
static pconf_entry *parse_list(pconf_context *,
			       int,
			       int *);
static pconf_entry *parse_entry(pconf_context *,
				char **,
				int *);
static char **read_list(pconf_context *,
			char **,
			int *,
			int);
static char *get_token(pconf_context *);


#ifndef FALSE
#define FALSE	0
#endif

#ifndef TRUE
#define TRUE	!FALSE
#endif

#define	EXPECT_EOL	TRUE
#define DONT_EXPECT_EOL	FALSE

#define IS_LVALUE	TRUE

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
    int error;

    pcontext.file = fopen(filename, "r");

    if (pcontext.file == NULL) {
	sprintf(pconf_error, "Couldn't open file %s: %s",
		filename, strerror(errno));
	return NULL;
    }

    pcontext.linenum = 0;
    pcontext.filename = filename;
    pcontext.delim = (delim ? delim : DEFAULT_DELIM);
    pcontext.buffer_read = FALSE;
    pcontext.whole_line = FALSE;

    entry = parse_list(&pcontext, DONT_EXPECT_EOL, &error);

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

	if (entry->strings) {
	    char **string = entry->strings;

	    while(*string) {
		free(*string);
		string++;
	    }
	    
	    free(entry->strings);
	}

	if (entry->values) {
	    char **string = entry->values;

	    while(*string) {
		free(*string);
		string++;
	    }
	    
	    free(entry->strings);
	}


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

    entry->strings = NULL;
    entry->type = CONF_TYPE_NONE;
    entry->values = NULL;
    entry->list = NULL;
    entry->next = NULL;

    return entry;
}



/*
 * Parse a configuration file. This reoutine is recursive in that if it
 * descents to a sublist (e.g. "sublist = { <sublist> }") it calls itself
 * on the sublist.
 *
 * If expect_eol is true, then this routine expects a "}" to end this
 * list, otherwise it expects EOF.
 */
static pconf_entry *
parse_list(pconf_context *pcontext,
	   int expect_eol,
	   int *error)
{
    pconf_entry *head = NULL;
    pconf_entry *current = NULL;
    char *string;


    while (TRUE) {
	if (current == NULL) {
	    /* First time through loop */
	    current = parse_entry(pcontext, &string, error);
	    head = current;
	} else {
	    current->next = parse_entry(pcontext, &string, error);
	    current = current->next;
	}

	if (*error)
	    goto error_return;

	if (string == NULL) {	/* EOF */
	    if (expect_eol) {
		sprintf(pconf_error, "Unexpected EOF on line %d of file %s",
			pcontext->linenum, pcontext->filename);
		goto error_return;
	    }
   
	    break;
	}
	    
	if (strcmp(string, "}") == 0) {
	    if (!expect_eol) {
		sprintf(pconf_error, "Unexpected } on line %d of file %s",
			pcontext->linenum, pcontext->filename);
		goto error_return;
	    }

	    break;
	}

	if (strcmp(string, ";") == 0)
	    continue;

	/* XXX Anything else to check for here ? */
    }

    return head;

error_return:
    /* Clean up all of our allocations and return NULL */
    free_pconf_enteries(head);
    return NULL;
}



/*
 * Read an entry and allocate a structure to hold it. Returns null if
 * there wasn't an entry to read (we're at EOL or EOF).
 *
 * terminator is set to point at the string that terminated the list
 * (will be NULL if it was terminated by EOF).
 *
 * Sets error if an error is encountered.
 */
static pconf_entry *
parse_entry(pconf_context *pcontext,
	    char **terminator,
	    int *error)
{
    pconf_entry	*entry;
    char *string;


    entry = new_pconf_entry();

    if (entry == NULL)
	goto error_return;

    /* Read Lvalues */
    entry->strings = read_list(pcontext, &string, error, IS_LVALUE);

    if (*error)
	goto error_return;

    if (string == NULL)	/* EOF */
	goto done;

    if (strcmp(string, ";") == 0)
	goto done;

    if (strcmp(string, "}") == 0)
	goto done;	/* Must be an empty list */

    /* Must have hit at "=" */
    entry->values = read_list(pcontext, &string, error, !IS_LVALUE);

    if (*error)
	goto error_return;

    /* Is it the start of another entry list? */
    if (strcmp(string, "{") == 0) {
	entry->type = CONF_TYPE_LIST;
	entry->list = parse_list(pcontext, EXPECT_EOL, error);
	if (*error)
	    goto error_return;
    } else {
	entry->type = CONF_TYPE_VALUE;
    }
	
   
done:
    *terminator = string;
    *error = FALSE;

    /*
     * Check and see if we actually read anything, and if not return null.
     */
    if (entry->strings == NULL) {
	free(entry);
	entry = NULL;
    }
    return entry;
    
error_return:
    if (entry)
	free_pconf_enteries(entry);
    *error = TRUE;
    return NULL;
}


/*
 * Read a list of strings stopping if a special character (;={}) or EOF
 * is reached (which is an error). The string with the specical character
 * is returned in terminator. If an error is encounted, NULL is returned
 * and error is set to 1, else 0.
 */
static char **
read_list(pconf_context *pcontext,
	  char **terminator,
	  int *error,
	  int is_lvalue)
{
    char	**list;
    char	*string;
    int		size = 10;	/* Initial size of array */
    int		num_items = 0;


    list = (char **) malloc(sizeof(char *) * size);

    if (list == NULL) {
	sprintf(pconf_error, "malloc() failed");
	goto error_return;
    }

    list[0] = NULL;
    
    while (string = get_token(pcontext)) {
	/* ; is always a legal terminator */
	if (strcmp(string, ";") == 0)
	    break;

	/* = is legal if this is a lvalue and we're read something*/
	if (strcmp(string, "=") == 0) {
	    if (is_lvalue && (num_items != 0))
		break;

	    sprintf(pconf_error, "Unexpected = on line %d of file %s",
		    pcontext->linenum, pcontext->filename);
	    goto error_return;
	}

	/*
	 * } is only legal if this is an lvalue and
	 * we haven't read anything
	 */
	if (strcmp(string, "}") == 0) {
	    if (is_lvalue && (num_items == 0))
		break;

	    sprintf(pconf_error, "Unexpected } on line %d of file %s",
		    pcontext->linenum, pcontext->filename);
	    goto error_return;
	}

	/*
	 * { is legal if this is not an lvalue and we haven't read
	 * anything.
	 */
	if (strcmp(string, "{") == 0) {
	    if (!is_lvalue && (num_items == 0))
		break;

	    sprintf(pconf_error, "Unexpected { on line %d of file %s",
		    pcontext->linenum, pcontext->filename);
	    goto error_return;
	}

	/*
	 * Add this string to the list, making sure we have enough space
	 * allocated.
	 */
	if ((num_items + 2) > size) {
	    size += 10;
	    list = (char **) realloc(list, sizeof(char *) * size);

	    if (list == NULL) {
		sprintf(pconf_error, "realloc() failed");
		goto error_return;
	    }
	}

	list[num_items] = strdup(string);
	num_items++;
	list[num_items] = NULL;
    }

    /* EOF is only legal if this is a lvalue and we haven't read anything */
    if (string == NULL)
	if (!(is_lvalue && (num_items == 0))) {
	    sprintf(pconf_error, "Unexpected EOF at line %d of file %s",
		    pcontext->linenum, pcontext->filename);
	    goto error_return;
	}

    if (num_items) {
	/* Trim array down to size, leaving room for terminating NULL */
	list = (char **) realloc(list, sizeof(char *) * (num_items + 1));

	if (list == NULL) {
	    sprintf(pconf_error, "realloc() failed");
	    goto error_return;
	}

	list[num_items] = NULL;

    } else {
	/* Nothing read */
	free(list);
	list = NULL;
    }

    *terminator = string;
    *error = FALSE;
    return list;
    
error_return:
    if (list) {
	char **string = list;

	while(*string) {
	    free(*string);
	    string++;
	}

	free(list);
    }
    *error = TRUE;
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
    int in_comment = FALSE;

    if (pcontext->buffer_read) {
	token = strtok(NULL, pcontext->delim);

	if (token && (*token == '#'))
	    in_comment = TRUE;
    }

    while ((token == NULL) || in_comment) {
	/*
	 * If we're in a comment then just read the rest of the
	 * line, if we haven't read the whole this, and discard it
	 */
	if (in_comment && (pcontext->whole_line == FALSE)) {
	    while(1) {
		if (fgets(buffer, BUFSIZE, pcontext->file) == NULL)
		    return NULL;

		if (buffer[strlen(buffer) - 1] == '\n')
		    break;
	    }
	}

	in_comment = FALSE;

	/* Read our next line to parse */
	if (fgets(buffer, BUFSIZE, pcontext->file) == NULL)
	    return NULL;

	pcontext->buffer_read = TRUE;

	/* Did we get a CR? */
	if (buffer[strlen(buffer) - 1] == '\n') {
	    (pcontext->linenum)++;
	    pcontext->whole_line = TRUE;
	} else {
	    pcontext->whole_line = FALSE;
	}

	token = strtok(buffer, pcontext->delim);

	if (token && (*token == '#'))
	    in_comment = TRUE;
    }

    return token;
}
