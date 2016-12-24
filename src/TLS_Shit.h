#pragma once
#include "dependencies.h"
#include "struct_url.hpp"

void errno_report(const char * where);
void ssl_error(ssize_t error, struct_url * url, const char * where);
void ssl_error_p(ssize_t error, struct_url * url, const char * where, const char * extra);


/* Functions to deal with gnutls_datum_t stolen from gnutls docs.
 * The structure does not seem documented otherwise.
 */
gnutls_datum_t load_file (const char *file);
void unload_file (gnutls_datum_t data);

/* This function will print some details of the
 * given session.
 *
 * Stolen from the GNUTLS docs.
 */
int print_ssl_info (gnutls_session_t session);

/* This function will try to verify the peer’s certificate, and
 * also check if the hostname matches, and the activation, expiration dates.
 *
 * Stolen from the gnutls manual.
 */
int verify_certificate_callback (gnutls_session_t session);
void logfunc(int level, const char * str);
void ssl_error_p(ssize_t error, struct_url * url, const char * where, const char * extra);
void ssl_error(ssize_t error, struct_url * url, const char * where);

