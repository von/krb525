/*
 * netio.h
 *
 * $Id: netio.h,v 1.2 1999/11/03 20:23:21 vwelch Exp $
 */

#ifndef __NETIO_H
#define __NETIO_H

#include "krb5.h"
#include "com_err.h"

extern char netio_error[];

extern int send_encrypt(krb5_context,
			krb5_auth_context,
			int,
			krb5_data);

extern int send_msg(krb5_context,
		    int,
		    krb5_data);

extern int send_value(krb5_context,
		      int,
		      int);

extern int read_encrypt(krb5_context,
			krb5_auth_context,
			int,
			krb5_data *);

extern int read_msg(krb5_context,
		    int,
		    krb5_data *);

extern int read_value(krb5_context,
		      int,
		      int *);

extern int connect_to_server(char *,
			     int);


extern int make_accepting_sock(int);



#endif /* __NETIO_H */
