/*
 * netio.c 
 *
 * krb525 network I/O routines
 *
 * $Id: netio.c,v 1.1 1997/09/08 15:41:33 vwelch Exp $
 */

/*
 *
 * Message sending overview:
 *
 * Each message consists of a 32 bit integer specifing the length of
 * the message in bytes, followed by the (possibly encrypted message).
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>


#include "netio.h"

char netio_error[256] = "No error";


/*
 *
 * Message sending overview:
 *
 * Each message consists of a 32 bit integer specifing the length of
 * the message in bytes, followed by the (possibly encrypted message).
 *
 */


int
send_encrypt(krb5_context context,
	     krb5_auth_context auth_context,
	     int fd,
	     krb5_data message)
{
    krb5_error_code	retval;
    krb5_data		emessage;


    /* Encrypt message */
    if (retval = krb5_mk_priv(context, auth_context, &message, &emessage,
			       NULL)) {
	sprintf(netio_error, "%s while encrypting message",
		error_message(retval));
	return retval;
    }
 
    if ((retval = send_msg(context, fd, emessage)) == -1)
	return -1;

    krb5_xfree(emessage.data);
    
    return retval;
}



int
send_msg(krb5_context context,
	 int fd,
	 krb5_data message)
{
    krb5_error_code	retval;


    /* Send message length */
    if ((retval = krb5_net_write(context, fd, (char *)&(message.length),
				 sizeof(message.length))) == -1) {
	sprintf(netio_error, "%s while writing message len",
		strerror(errno));
	return -1;
    }

    /* Send message */
    if ((retval = krb5_net_write(context, fd, message.data,
				 message.length)) == -1) {
	sprintf(netio_error, "%s while writing message",
		strerror(errno));
	return -1;
    }
    
    return 0;
}



int
read_encrypt(krb5_context context,
	     krb5_auth_context auth_context,
	     int fd,
	     krb5_data *message)
{
    krb5_error_code	retval;
    krb5_data		emessage;


    /* Read encrypted message */
    if ((retval = read_msg(context, fd, &emessage)) == -1) {
	return -1;
    }

    /* Decrypt the message */
    if (retval = krb5_rd_priv(context, auth_context, &emessage, message,
			      NULL)) {
	sprintf(netio_error, "%s decrypting target from client",
		error_message(retval));
	return -1;
    }

    krb5_xfree(emessage.data);
    return retval;
}



read_msg(krb5_context context,
	 int fd,
	 krb5_data *message)
{
    krb5_error_code	retval;

    
    /* Read message length */
    if ((retval = krb5_net_read(context, fd, (char *)&(message->length),
			       sizeof(message->length))) <= 0) {
	if (retval == 0)
	    errno = ECONNABORTED;
	sprintf(netio_error, "%s reading message length",
		strerror(errno));
	return -1;
    }

    if ((message->data = (char *) malloc(message->length)) == NULL) {
	sprintf(netio_error, "malloc() failed: %s",
		strerror(errno));
	return -1;
    }

    if ((retval = krb5_net_read(context, fd, message->data,
			       message->length)) <= 0) {
	if (retval == 0)
	    errno = ECONNABORTED;
	sprintf(netio_error, "%s reading message",
		strerror(errno));
	message->length = 0;
	krb5_xfree(message->data);
	return -1;
    }

    return retval;
}


/*
 * Given a hostname and port, connect. Returns the socket descriptor
 * or -1 on error, setting the string netio_error to a description
 * of the error.
 */

int
connect_to_server(char *hostname,
		  int port)
{
    struct sockaddr_in	sin;
    struct hostent	*hp;
    int			sock;


    /* clear out the structure first */
    (void) memset((char *)&sin, 0, sizeof(sin));

    /* look up the server host */
    hp = gethostbyname(hostname);
    if (!hp) {
	sprintf(netio_error, "unknown host %s\n", hostname);
	return -1;
    }

    /* set up the address of the foreign socket for connect() */
    sin.sin_family = hp->h_addrtype;
    (void) memcpy((char *)&sin.sin_addr,
		  (char *)hp->h_addr,
		  sizeof(hp->h_addr));
    sin.sin_port = htons(port);

    /* open a TCP socket */
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
	sprintf(netio_error, "socket()");
	return -1;
    }

    /* connect to the server */
    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	sprintf(netio_error, "Connection to %s port %d failed: %s.",
		hostname, port, strerror(errno));
	close(sock);
	return -1;
    }

    return sock;
}



/*
 * Make an accepting socket listening on given port number.
 */
int
make_accepting_sock(int port)
{
    int		sock;
    int		on = 1;
    struct sockaddr_in addr;


    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	sprintf(netio_error, "socket() call failed: %s",
		strerror(errno));
	return -1;
    }

    /* Let the socket be reused right away */
    (void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
		      sizeof(on));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0;
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
	sprintf(netio_error, "bind() call failed: %s",
		strerror(errno));
	close(sock);
	return -1;
    }

    if (listen(sock, 5) == -1) {
	sprintf(netio_error, "listen() call failed: %s",
		strerror(errno));
	close(sock);
	return -1;
    }

    return sock;
}
