/*
 * parse_conf.h
 *
 * $Id: parse_conf.h,v 1.1 1997/09/08 15:41:33 vwelch Exp $
 *
 */

#ifndef __CONF_H
#define __CONF_H

extern char pconf_error[];


struct _pconf_entry {
    char *string;	
    int type;
    char *value;
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
