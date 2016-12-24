#include "dependencies.h"
#include "httpfs2.hpp"
#include "TLS_Shit.h"

/* Functions to deal with gnutls_datum_t stolen from gnutls docs.
 * The structure does not seem documented otherwise.
 */
gnutls_datum_t load_file (const char *file)
{
	FILE *f;
	gnutls_datum_t loaded_file = { NULL, 0 };
	long filelen;
	void *ptr;
	f = fopen (file, "r");
	if (!f)
		errno_report(file);
	else if (fseek (f, 0, SEEK_END) != 0)
		errno_report(file);
	else if ((filelen = ftell (f)) < 0)
		errno_report(file);
	else if (fseek (f, 0, SEEK_SET) != 0)
		errno_report(file);
	else if (!(ptr = malloc ((size_t) filelen)))
		errno_report(file);
	else if (fread (ptr, 1, (size_t) filelen, f) < (size_t) filelen)
		errno_report(file);
	else {
		loaded_file.data = (unsigned char*)ptr;
		loaded_file.size = (unsigned int) filelen;
		fprintf(stderr, "Loaded '%s' %ld bytes\n", file, filelen);
		/* fwrite(ptr, filelen, 1, stderr); */
	}
	return loaded_file;
}

void unload_file (gnutls_datum_t data)
{
	free (data.data);
}

/* This function will print some details of the
 * given session.
 *
 * Stolen from the GNUTLS docs.
 */
int print_ssl_info (gnutls_session_t session)
{
	const char *tmp;
	gnutls_credentials_type_t cred;
	gnutls_kx_algorithm_t kx;
	int dhe, ecdh;
	dhe = ecdh = 0;
	if (!session) {
		fprintf(stderr, "No SSL session data.\n");
		return 0;
	}
	//print the key exchange’s algorithm name
	kx = gnutls_kx_get (session);
	tmp = gnutls_kx_get_name (kx);
	fprintf(stderr, "- Key Exchange: %s\n", tmp);
	//Check the authentication type used and switch to the appropriate.
	cred = gnutls_auth_get_type (session);
	switch (cred)
	{
		case GNUTLS_CRD_CERTIFICATE:
			//certificate authentication
			//Check if we have been using ephemeral Diffie-Hellman.
			if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS)
				dhe = 1;
			else if (kx == GNUTLS_KX_ECDHE_RSA || kx == GNUTLS_KX_ECDHE_ECDSA)
				ecdh = 1;
			//cert should have been printed when it was verified
			break;
		default:
			fprintf(stderr, "Not a x509 sesssion !?!\n");

	}
	//switch
	if (ecdh != 0)
		fprintf(stderr, "- Ephemeral ECDH using curve %s\n", gnutls_ecc_curve_get_name (gnutls_ecc_curve_get (session)));
	else
		if (dhe != 0)
			fprintf(stderr, "- Ephemeral DH using prime of %d bits\n",
					gnutls_dh_get_prime_bits (session));
	//print the protocol’s name (ie TLS 1.0)
	tmp = gnutls_protocol_get_name (gnutls_protocol_get_version (session));
	fprintf(stderr, "- Protocol: %s\n", tmp);
	//print the certificate type of the peer. ie X.509
	tmp =
		gnutls_certificate_type_get_name (gnutls_certificate_type_get (session));
	fprintf(stderr, "- Certificate Type: %s\n", tmp);
	//print the compression algorithm (if any)
	tmp = gnutls_compression_get_name (gnutls_compression_get (session));
	fprintf(stderr, "- Compression: %s\n", tmp);
	//print the name of the cipher used. ie 3DES.
	tmp = gnutls_cipher_get_name (gnutls_cipher_get (session));
	fprintf(stderr, "- Cipher: %s\n", tmp);
	//Print the MAC algorithms name. ie SHA1
	tmp = gnutls_mac_get_name (gnutls_mac_get (session));
	fprintf(stderr, "- MAC: %s\n", tmp);
	fprintf(stderr, "Note: SSL paramaters may change as new connections are established to the server.\n");
	return 0;
}

/* This function will try to verify the peer’s certificate, and
 * also check if the hostname matches, and the activation, expiration dates.
 *
 * Stolen from the gnutls manual.
 */
int verify_certificate_callback (gnutls_session_t session)
{
	unsigned int status;
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size;
	int ret;
	gnutls_x509_crt_t cert;
	gnutls_datum_t data = {0};
	struct_url * url = (struct_url *) gnutls_session_get_ptr (session);
	const char *hostname = url->host;

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2 (session, &status);
	if (ret < 0)
	{
		ssl_error(ret, url, "verify certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	if (status & GNUTLS_CERT_INVALID)
		fprintf(stderr, "The server certificate is NOT trusted.\n");
	if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
		fprintf(stderr, "The server certificate uses an insecure algorithm.\n");
	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		fprintf(stderr, "The server certificate hasn’t got a known issuer.\n");
	if (status & GNUTLS_CERT_REVOKED)
		fprintf(stderr, "The server certificate has been revoked.\n");
	if (status & GNUTLS_CERT_EXPIRED)
		fprintf(stderr, "The server certificate has expired\n");
	if (status & GNUTLS_CERT_NOT_ACTIVATED)
		fprintf(stderr, "The server certificate is not yet activated\n");
	/* Up to here the process is the same for X.509 certificates and
	 * OpenPGP keys. From now on X.509 certificates are assumed. This can
	 * be easily extended to work with openpgp keys as well.
	 */
	if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
		return GNUTLS_E_CERTIFICATE_ERROR;
	if (gnutls_x509_crt_init (&cert) < 0)
	{
		ssl_error(ret, url, "verify certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
	if (cert_list == NULL)
	{
		fprintf(stderr, "No server certificate was found!\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	/* Check the hostname matches the certificate. */
	ret = gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER);
	if (ret < 0)
	{
		ssl_error(ret, url, "parsing certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	if (!(url->ssl_connected)) if (!gnutls_x509_crt_print (cert, GNUTLS_CRT_PRINT_FULL, &data)) {
		fprintf(stderr, "%s", data.data);
		gnutls_free(data.data);
	}
	if (!hostname || !gnutls_x509_crt_check_hostname (cert, hostname))
	{
		int found = 0;
		if (hostname) {
			int i;
			size_t len = strlen(hostname);
			if (*(hostname+len-1) == '.') len--;
			if (!(url->ssl_connected)) fprintf(stderr, "Server hostname verification failed. Trying to peek into the cert.\n");
			for (i=0;;i++) {
				char * dn = NULL;
				size_t dn_size = 0;
				int dn_ret = 0;
				int match=0;
				gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, i, 0, dn, &dn_size);
				if (dn_size) dn = new char[dn_size + 1]; /* nul not counted */
				if (dn)
					dn_ret = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, i, 0, dn, &dn_size);
				if (!dn_ret){
					if (dn) {
						if (*(dn+dn_size-1) == '.') dn_size--;
						if (len == dn_size)
							match = ! strncmp(dn, hostname, len);
						if (match) found = 1;
						if (!(url->ssl_connected)) fprintf(stderr, "Cert CN(%i): %s: %c\n", i, dn, match?'*':'X');
					}}
				else
					ssl_error(dn_ret, url, "getting cert subject data");
				if (dn) free(dn);
				if (dn_ret || !dn)
					break;
			}
		}
		if(!found){
			fprintf(stderr, "The server certificate’s owner does not match hostname ’%s’\n",
					hostname);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
	}
	gnutls_x509_crt_deinit (cert);
	/*
	 * It the status includes GNUTLS_CERT_INVALID whenever
	 * there is a problem and the other flags are just informative.
	 */
	if (status & GNUTLS_CERT_INVALID)
		return GNUTLS_E_CERTIFICATE_ERROR;
	/* notify gnutls to continue handshake normally */
	return 0;
}

void logfunc(int level, const char * str)
{
	fputs(str, stderr);
}

void ssl_error_p(ssize_t error, struct_url * url, const char * where, const char * extra)
{
	const char * err_desc;
	if((error == GNUTLS_E_FATAL_ALERT_RECEIVED) || (error == GNUTLS_E_WARNING_ALERT_RECEIVED))
		err_desc = gnutls_alert_get_name(gnutls_alert_get(url->ss));
	else
		err_desc = gnutls_strerror((int)error);

	fprintf(stderr, "%s: %s: %s: %s%zd %s.\n", argv0, url->tname, where, extra, error, err_desc);
}

void ssl_error(ssize_t error, struct_url * url, const char * where)
{
	ssl_error_p(error, url, where, "");
	/* FIXME try to decode errors more meaningfully */
	errno = EIO;
}

