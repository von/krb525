/*
 * auth_con.c
 *
 * Functions dealing with Kerberos auth_context.
 *
 * $Id: auth_con.c,v 1.3 1997/10/17 19:32:36 vwelch Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "auth_con.h"

char auth_con_error[255] = "No error";


/* XXX - check for cleanup */
krb5_error_code
setup_auth_context(krb5_context context,
		   krb5_auth_context auth_context,
		   struct sockaddr_in *localaddr,
		   struct sockaddr_in *remoteaddr,
		   char *uniq)
{
    krb5_address  	laddr, raddr, *portlocal_addr;
    krb5_rcache 	rcache;
    krb5_data		rcache_name;
    char       		*outaddr;
    krb5_error_code	retval;


    laddr.addrtype = ADDRTYPE_IPPORT;
    laddr.length = sizeof(localaddr->sin_port);
    laddr.contents = (krb5_octet *)&(localaddr->sin_port);

    raddr.addrtype = ADDRTYPE_IPPORT;
    raddr.length = sizeof(remoteaddr->sin_port);
    raddr.contents = (krb5_octet *)&(remoteaddr->sin_port);

    if (retval = krb5_auth_con_setports(context, auth_context,
					 &laddr, &raddr)) {
	sprintf(auth_con_error, "%s while setting auth_con ports\n",
		error_message(retval));
	return retval;
    }

    laddr.addrtype = ADDRTYPE_INET;
    laddr.length = sizeof(localaddr->sin_addr);
    laddr.contents = (krb5_octet *)&(localaddr->sin_addr);

    raddr.addrtype = ADDRTYPE_INET;
    raddr.length = sizeof(remoteaddr->sin_addr);
    raddr.contents = (krb5_octet *)&(remoteaddr->sin_addr);

    if (retval = krb5_auth_con_setaddrs(context, auth_context,
					 &laddr, &raddr)) {
	sprintf(auth_con_error, "%s while setting auth_con addresses\n",
		error_message(retval));
	return retval;
    }


    /* Set up replay cache */ 
    if ((retval = krb5_gen_portaddr(context,
				    &laddr,
				    (krb5_pointer) &(localaddr->sin_port),
				    &portlocal_addr))) {
	sprintf(auth_con_error, "%s while generating port address",
		error_message(retval));
	return retval;
    }
    
    if ((retval = krb5_gen_replay_name(context, portlocal_addr,
				       uniq, &outaddr))) {
	sprintf(auth_con_error, "%s while generating replay cache name",
		error_message(retval));
	return retval;
    }

    rcache_name.length = strlen(outaddr);
    rcache_name.data = outaddr;

    if ((retval = krb5_get_server_rcache(context, &rcache_name, &rcache))) {
	sprintf(auth_con_error, "%s while getting server rcache",
		error_message(retval));
	return retval;
    }

    if (retval = krb5_auth_con_setrcache(context, auth_context, rcache)) {
	sprintf(auth_con_error, "%s setting rcache",
		error_message(retval));
	return retval;
    }
	
    return retval;
}


