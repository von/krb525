/*
 * k5_db.c
 *
 * Deal with kerberos database.
 *
 * $Id: k5_db.c,v 1.1 1997/09/08 15:41:33 vwelch Exp $
 */


#include <krb5.h>
#include <kadm5/admin.h>
#include <com_err.h>

#include "k5_db.h"


char k5_db_error[255] = "No Error";

static void *handle;

/*
 * Initialize database
 */

int
k5_db_init(char * whoami,
	   krb5_context context,
	   kadm5_config_params *params)
{
    int			 retval;


    if ((retval = kadm5_init(whoami, NULL, KADM5_ADMIN_SERVICE, params,
			  KADM5_STRUCT_VERSION, KADM5_API_VERSION_2,
			  &handle))) {
	sprintf(k5_db_error, "%s initializing kadm5 library",
		error_message(retval));
	return -1;	
    }
} 



/*
 * Close database
 */

void
k5_db_close(krb5_context context)
{
    (void) kadm5_destroy(handle);
}


/*
 * Given a principal and a key type, retreive the key
 */

krb5_error_code
k5_db_get_key(krb5_context context,
	      krb5_principal princ,
	      krb5_keyblock *key,
	      krb5_enctype ktype)
{
    krb5_error_code		retval;
    kadm5_principal_ent_rec	princ_ent;


    if (retval = kadm5_get_principal(handle, princ,
				      &princ_ent, KADM5_KEY_DATA)) {
	sprintf(k5_db_error, "%s get principal information",
		error_message(retval));
	return retval;
    }

    if (retval = kadm5_decrypt_key(handle,
				   &princ_ent,
				   ktype,
				   -1,
				   -1,
				   key,
				   NULL,
				   NULL))
	sprintf(k5_db_error, "%s decrypting key",
		error_message(retval));

    kadm5_free_principal_ent(handle, &princ_ent);
    return retval;
}

    

