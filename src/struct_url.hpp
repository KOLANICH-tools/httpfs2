#pragma once
#include "dependencies.h"
#include "httpfs2.hpp"
#include "sock_state.hpp"
#include "url_flags.hpp"

struct struct_url {
	int proto;
	long timeout;
	char * url;
	char * host; /*hostname*/
	int port;
	char * path; /*get path*/
	char * name; /*file name*/
#ifdef USE_AUTH
	char * auth; /*encoded auth data*/
#endif
#ifdef RETRY_ON_RESET
	long retry_reset; /*retry reset connections*/
	long resets;
#endif
	int sockfd;
	sock_state sock_type;
	int redirected;
	int redirect_followed;
	int redirect_depth;
#ifdef USE_SSL
	long ssl_log_level;
	unsigned md5;
	unsigned md2;
	int ssl_initialized;
	int ssl_connected;
	gnutls_certificate_credentials_t sc;
	gnutls_session_t ss;
	const char * cafile;
#endif
	char * req_buf;
	size_t req_buf_size;
	off_t file_size;
	time_t last_modified;
	char tname[TNAME_LEN + 1];
	char xmd5[33];
};
 
static struct_url main_url;

 /*
 * functions for handling struct_url
 */


int init_url(struct_url* url);
int free_url(struct_url* url);

static const char* qexclqStr="?!?";
static const char* httpStr="http";
static const char* httpsStr="https";
static const char* httpPrStr="http://";
static const char* httpsPrStr="https://";

void print_url(FILE *f, const struct_url * url);
int parse_url(char * _url, struct_url* res, url_flags flag);

#ifdef USE_THREAD

void destroy_url_copy(void * urlptr);
struct_url * create_url_copy(const struct_url * url);

struct_url * thread_setup(void);

#else /*USE_THREAD*/
struct_url * thread_setup(void);
#endif


/*
 * Socket operations that abstract ssl and keepalive as much as possible.
 * Keepalive is set when parsing the headers.
 *
 */

#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif

sock_state close_client_force(struct_url *url);
sock_state close_client_socket(struct_url *url);
ssize_t read_client_socket(struct_url *url, void * buf, size_t len);
ssize_t write_client_socket(struct_url *url, const void * buf, size_t len);
/*
 * Function yields either a positive int after connecting to
 * host 'hostname' on port 'port'  or < 0 in case of error
 *
 * It handles keepalive by not touching keepalive sockets.
 * The SSL context is created so that read/write can use it.
 *
 * hostname is something like 'www.tmtd.de' or 192.168.0.86
 * port is expected in machine order (not net order)
 *
 * ((Flonix  defines USE_IPV6))
 *
 */
sock_state open_client_socket(struct_url *url);

#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif
