/*
 * parse_conf.h
 *
 * $Id: parse_conf.h,v 1.2 1997/09/17 16:58:00 vwelch Exp $
 *
 */

#ifndef __CONF_H
#define __CONF_H

extern char pconf_error[];


struct _pconf_entry {
    char **strings;	
    int type;
    char **values;
    struct _pconf_entry *list;
    struct _pconf_entry *next;
};

typedef struct _pconf_entry pconf_entry;


#define CONF_TYPE_NONE		0
#define CONF_TYPE_VALUE		1
#define	CONF_TYPE_LIST		2

extern pconf_entry *parse_conf(char *,
			       char *);
extern void free_pconf_enteries(pconf_entry *);



#endif /* __CONF_H */
