/*
 * k5_db.h
 *
 * $Id: k5_db.h,v 1.2 1997/09/17 16:57:58 vwelch Exp $
 */

#ifndef __K5_DB_H
#define __K5_DB_H

#include <krb5.h>
#include <kadm5/admin.h>
#include <com_err.h>

extern int k5_db_init(char *,
		      krb5_context,
		      kadm5_config_params *);

extern void k5_db_close(krb5_context);

krb5_error_code k5_db_get_key(krb5_context,
			      krb5_principal,
			      krb5_keyblock *,
			      krb5_enctype);

krb5_error_code k5_db_get_entry(krb5_context,
				krb5_principal,
				krb5_db_entry *);

extern char k5_db_error[];


#endif /* __K5_DB_H */
