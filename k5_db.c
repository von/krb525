/*
 * k5_db.c
 *
 * Deal with kerberos database.
 *
 * $Id: k5_db.c,v 1.2 1997/09/17 16:57:57 vwelch Exp $
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

    /*
     * kadm5_init() is sufficient to get keys out of the database, but in
     * order to get whole entries (with krb5_db_get_principal()) we also
     * need to call krb5_dbm_db_init(). *shrug*
     */

    if ((retval = kadm5_init(whoami, NULL, KADM5_ADMIN_SERVICE, params,
			  KADM5_STRUCT_VERSION, KADM5_API_VERSION_2,
			  &handle))) {
	sprintf(k5_db_error, "%s initializing kadm5 library",
		error_message(retval));
	return -1;	
    }

    if (retval = krb5_dbm_db_init(context)) {
	sprintf(k5_db_error,
		"%s initializing database routines (krb5_dbm_db_init())",
		error_message(retval));
	return -1;
    }

    return 0;
} 



/*
 * Close database
 */

void
k5_db_close(krb5_context context)
{
    (void) krb5_dbm_db_fini(context);
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


/*
 * Given a principal, retreive it's DB entry
 *
 * From kdc/do_as_req.c:process_as_req()
 */
krb5_error_code
k5_db_get_entry(krb5_context context,
		krb5_principal princ,
		krb5_db_entry *entry)
{
    int			nprincs = 1;
    krb5_boolean	more;
    krb5_error_code	retval;

    
    if (retval = krb5_db_get_principal(context, princ, entry, &nprincs, &more)) {
	sprintf(k5_db_error, "%s looking up principal",
		error_message(retval));
	return retval;
    }

    if (more) {
	sprintf(k5_db_error, "Non-unique principal");
	return KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
    }

    if (nprincs != 1) {
	sprintf(k5_db_error, "Principal not found");
	return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
    }

    return retval;
}



    
    

