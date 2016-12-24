#include "struct_url.hpp"
#include "httpfs2.hpp"
#include "TLS_Shit.h"
#include "Utils.hpp"
#include "base64.hpp"

 /*
 * functions for handling struct_url
 */


int init_url(struct_url* url)
{
	memset(url, 0, sizeof(*url));
	url->sock_type = sock_state::SOCK_CLOSED;
	url->timeout = TIMEOUT;
#ifdef RETRY_ON_RESET
	url->retry_reset = RESET_RETRIES;
#endif
#ifdef USE_SSL
	url->cafile = CERT_STORE;
#endif
	return 0;
}

int free_url(struct_url* url)
{
	if(url->sock_type != sock_state::SOCK_CLOSED)
		close_client_force(url);
	if(url->host) delete[](url->host);
	url->host = 0;
	if(url->path) delete[](url->path);
	url->path = 0;
	if(url->name) delete[](url->name);
	url->name = 0;
#ifdef USE_AUTH
	if(url->auth) free(url->auth);
	url->auth = 0;
#endif
	url->port = 0;
	url->proto = 0; /* only after socket closed */
	url->file_size=0;
	url->last_modified=0;
	return 0;
}

void print_url(FILE *f, const struct_url * url)
{
	char * protocol = const_cast<char*>(qexclqStr);
	switch(url->proto){
		case PROTO_HTTP:
			protocol = const_cast<char*>(httpStr);
			break;;
#ifdef USE_SSL
		case PROTO_HTTPS:
			protocol = const_cast<char*>(httpsStr);
			break;;
#endif
	}
	fprintf(f, "file name: \t%s\n", url->name);
	fprintf(f, "host name: \t%s\n", url->host);
	fprintf(f, "port number: \t%d\n", url->port);
	fprintf(f, "protocol: \t%s\n", protocol);
	fprintf(f, "request path: \t%s\n", url->path);
#ifdef USE_AUTH
	fprintf(f, "auth data: \t%s\n", url->auth ? "(present)" : "(null)");
#endif
}

int parse_url(char * _url, struct_url* res, url_flags flag)
{
	const char * url_orig;
	const char * url;
	const char * http = httpPrStr;
#ifdef USE_SSL
	const char * https = httpsPrStr;
#endif /* USE_SSL */
	int path_start = '/';

	if (!_url)
		_url = res->url;
	assert(_url);
	switch(flag) {
		case url_flags::URL_DUP:
			_url = strdup(_url);
		[[clang::fallthrough]];
		case url_flags::URL_SAVE:
			assert (_url != res->url);
			if (res->url)
				free(res->url);
			res->url = _url;
			break;
		case url_flags::URL_DROP:
			assert (res->url);
			break;
	}
	/* constify so compiler warns about modification */
	url_orig = url = _url;

	close_client_force(res);
#ifdef USE_SSL
	res->ssl_connected = 0;
#endif

	if (strncmp(http, url, strlen(http)) == 0) {
		url += strlen(http);
		res->proto = PROTO_HTTP;
		res->port = 80;
#ifdef USE_SSL
	} else if (strncmp(https, url, strlen(https)) == 0) {
		url += strlen(https);
		res->proto = PROTO_HTTPS;
		res->port = 443;
#endif /* USE_SSL */
	} else {
		fprintf(stderr, "Invalid protocol in url: %s\n", url_orig);
		return -1;
	}

	/* determine if path was given */
	if(res->path)
		free(res->path);
	if(strchr(url, path_start))
		res->path = url_encode(strchr((char *)url, path_start));
	else{
		path_start = 0;
		res->path = strdup("/");
	}


#ifdef USE_AUTH
	/* Get user and password */
	if(res->auth)
		free(res->auth);
	if(strchr(url, '@') && (strchr(url, '@') < strchr(url, path_start))){
		res->auth = b64_encode((unsigned char *)url, strchr(url, '@') - url);
		url = strchr(url, '@') + 1;
	}else{
		res->auth = 0;
	}
#endif /* USE_AUTH */

	/* Get port number. */
	int host_end = path_start;
	if(strchr(url, ':') && (strchr(url, ':') < strchr(url, path_start))){
		/* FIXME check that port is a valid numeric value */
		res->port = atoi(strchr(url, ':') + 1);
		if (! res->port) {
			fprintf(stderr, "Invalid port in url: %s\n", url_orig);
			return -1;
		}
		host_end = ':';
	}
	/* Get the host name. */
	if (url == strchr(url, host_end)){ /*no hastname in the url */
		fprintf(stderr, "No hostname in url: %s\n", url_orig);
		return -1;
	}
	if(res->host)
		free(res->host);
	res->host = strndup(url, (size_t)(strchr(url, host_end) - url));

	if(flag != url_flags::URL_DROP) {
		/* Get the file name. */
		url = strchr(url, path_start);
		const char * end = url + strlen(url);
		end--;

		/* Handle broken urls with multiple slashes. */
		while((end > url) && (*end == '/')) end--;
		end++;
		if(res->name)
			free(res->name);
		if((path_start == 0) || (end == url)
				|| (strncmp(url, "/", (size_t)(end - url)) ==  0)){
			res->name = strdup(res->host);
		}else{
			while(strchr(url, '/') && (strchr(url, '/') < end))
				url = strchr(url, '/') + 1;
			res->name = strndup(url, (size_t)(end - url));
		}
	} else
		assert(res->name);

	return res->proto;
}

#ifdef USE_THREAD

void destroy_url_copy(void * urlptr)
{
	if(urlptr){
		fprintf(stderr, "%s: Thread %08lX ended.\n", argv0, pthread_self()); /*DEBUG*/
		free_url((struct_url*)urlptr);
		free(urlptr);
	}
}

struct_url * create_url_copy(const struct_url * url)
{
	struct_url * res = new struct_url(*url);
	if(url->name)
		res->name = strdup(url->name);
	if(url->host)
		res->host = strdup(url->host);
	if(url->path)
		res->path = strdup(url->path);
#ifdef USE_AUTH
	if(url->auth)
		res->auth = strdup(url->auth);
#endif
	memset(res->tname, 0, TNAME_LEN + 1);
	snprintf(res->tname, TNAME_LEN, "%0*lX", TNAME_LEN, pthread_self());
	return res;
}

struct_url * thread_setup(void)
{
	struct_url * res = (struct_url *) pthread_getspecific(url_key);
	if(!res) {
		fprintf(stderr, "%s: Thread %08lX started.\n", argv0, pthread_self()); /*DEBUG*/
		res = create_url_copy(&main_url);
		pthread_setspecific(url_key, res);
	}
	return res;
}

#else /*USE_THREAD*/
static struct_url * thread_setup(void) { return &main_url; }
#endif


/*
 * Socket operations that abstract ssl and keepalive as much as possible.
 * Keepalive is set when parsing the headers.
 *
 */

sock_state close_client_force(struct_url *url) {
	int SOCK_CLOSED = 0;

	if(url->sock_type != sock_state::SOCK_CLOSED){
		fprintf(stderr, "%s: %s: closing socket.\n", argv0, url->tname); /*DEBUG*/
#ifdef USE_SSL
		if (url->proto == PROTO_HTTPS) {
			fprintf(stderr, "%s: %s: closing SSL socket.\n", argv0, url->tname);
			gnutls_bye(url->ss, GNUTLS_SHUT_RDWR);
			gnutls_deinit(url->ss);
		}
#endif
		close(url->sockfd);
		SOCK_CLOSED = 1;
	}
	url->sock_type = sock_state::SOCK_CLOSED;

	if(url->redirected && url->redirect_followed) {
		fprintf(stderr, "%s: %s: returning from redirect to master %s\n", argv0, url->tname, url->url);
		if (SOCK_CLOSED) url->redirect_depth = 0;
		url->redirect_followed = 0;
		url->redirected = 0;
		parse_url(NULL, url, url_flags::URL_DROP);
		print_url(stderr, url);
		return sock_state::SOCK_EAGAIN;
	}
	return url->sock_type;
}

sock_state close_client_socket(struct_url *url) {
	if (url->sock_type == sock_state::SOCK_KEEPALIVE) {
		fprintf(stderr, "%s: %s: keeping socket open.\n", argv0, url->tname); /*DEBUG*/
		return sock_state::SOCK_KEEPALIVE;
	}
	return close_client_force(url);
}

ssize_t read_client_socket(struct_url *url, void * buf, size_t len) {
	ssize_t res;
	struct timeval timeout;
	timeout.tv_sec = url->timeout;
	timeout.tv_usec = 0;
	setsockopt(url->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#ifdef USE_SSL
	if (url->proto == PROTO_HTTPS) {
		do {
			res = gnutls_record_recv(url->ss, buf, len);
		} while ((res < 0) && handle_ssl_error(url, &res, "read"));
		if (res <= 0) ssl_error(res, url, "read");
	} else
#endif
	{
		res = read(url->sockfd, buf, len);
		if (res <= 0) errno_report("read");
	}
	return res;
}

ssize_t write_client_socket(struct_url *url, const void * buf, size_t len)
{
	do {
		sock_state fd = open_client_socket(url);
		ssize_t res;

		if ((int)fd < 0) return -1; /*error hopefully reported by open*/
#ifdef USE_SSL
		if (url->proto == PROTO_HTTPS) {
			do {
				res = gnutls_record_send(url->ss, buf, len);
			} while ((res < 0) && handle_ssl_error(url, &res, "write"));
			if (res <= 0) ssl_error(res, url, "write");
		} else
#endif
		{
			res = write(url->sockfd, buf, len);
			if (res <= 0) errno_report("write");
		}
		if ( !(res <= 0) || (url->sock_type != sock_state::SOCK_KEEPALIVE )) return res;

		/* retry a failed keepalive socket */
		close_client_force(url);
	} while (url->sock_type == sock_state::SOCK_KEEPALIVE);
	return -1; /*should not reach*/
}

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
sock_state open_client_socket(struct_url *url) {
#ifdef USE_IPV6
	struct addrinfo hints;
	char portstr[10];
	int gaierr;
	struct addrinfo* ai;
	struct addrinfo* aiv4;
	struct addrinfo* aiv6 = 0;
	struct sockaddr_in6 sa;
#else /* USE_IPV6 */
	struct hostent *he;
	struct sockaddr_in sa;
#endif /* USE_IPV6 */
	socklen_t sa_len;
	int sock_family, sock_type, sock_protocol;

	if(url->sock_type == sock_state::SOCK_KEEPALIVE) {
		fprintf(stderr, "%s: %s: reusing keepalive socket.\n", argv0, url->tname); /*DEBUG*/
		return url->sock_type;
	}

	if(url->sock_type != sock_state::SOCK_CLOSED) close_client_socket(url);

	if (url->redirected)
		url->redirect_followed = 1;

	fprintf(stderr, "%s: %s: connecting to %s port %i.\n", argv0, url->tname, url->host, url->port);

	(void) memset((void*) &sa, 0, sizeof(sa));

#ifdef USE_IPV6
	(void) memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	(void) snprintf(portstr, sizeof(portstr), "%d", (int) url->port);
	if ((gaierr = getaddrinfo(url->host, portstr, &hints, &ai)) != 0) {
		(void) fprintf(stderr, "%s: %s: getaddrinfo %s - %s\n",
				argv0, url->tname, url->host, gai_strerror(gaierr));
		errno = EIO;
		return (sock_state) -1;
	}

	/* Find the first IPv4 and IPv6 entries. */
	for (aiv4 = ai; aiv4 != NULL; aiv4 = aiv4->ai_next) {
		if (aiv4->ai_family == AF_INET)
			break;
		if ((aiv4->ai_family == AF_INET6) && (aiv6 == NULL))
			aiv6 = aiv4;
	}

	/* If there's an IPv4 address, use that, otherwise try IPv6. */
	if (aiv4 == NULL)
		aiv4 = aiv6;
	if (aiv4 == NULL) {
		(void) fprintf(stderr, "%s: %s: no valid address found for host %s\n",
				argv0, url->tname, url->host);
		errno = EIO;
		return (sock_state) -1;
	}
	if (sizeof(sa) < aiv4->ai_addrlen) {
		(void) fprintf(stderr, "%s: %s: %s - sockaddr too small (%lu < %lu)\n",
				argv0, url->tname, url->host, (unsigned long) sizeof(sa),
				(unsigned long) aiv4->ai_addrlen);
		errno = EIO;
		return (sock_state) -1;
	}
	sock_family = aiv4->ai_family;
	sock_type = aiv4->ai_socktype;
	sock_protocol = aiv4->ai_protocol;
	sa_len = aiv4->ai_addrlen;
	(void) memmove(&sa, aiv4->ai_addr, sa_len);
	freeaddrinfo(ai);

#else /* USE_IPV6 */

	he = gethostbyname(url->host);
	if (he == NULL) {
		(void) fprintf(stderr, "%s: %s: unknown host - %s\n", argv0, url->tname, url->host);
		errno = EIO;
		return -1;
	}
	sock_family = sa.sin_family = he->h_addrtype;
	sock_type = SOCK_STREAM;
	sock_protocol = 0;
	sa_len = sizeof(sa);
	(void) memmove(&sa.sin_addr, he->h_addr, he->h_length);
	sa.sin_port = htons(url->port);

#endif /* USE_IPV6 */

	url->sockfd = socket(sock_family, sock_type, sock_protocol);
	if (url->sockfd < 0) {
		errno_report("couldn't get socket");
		return (sock_state) -1;
	}
	if (connect(url->sockfd, (struct sockaddr*) &sa, sa_len) < 0) {
		errno_report("couldn't connect socket");
		return (sock_state) -1;
	}

#ifdef USE_SSL
	if ((url->proto) == PROTO_HTTPS) {
		/* Make SSL connection. */
		ssize_t r = 0;
		const char * ps = "NORMAL"; /* FIXME allow user setting */
		const char * errp = NULL;
		if (!url->ssl_initialized) {
			r = gnutls_global_init();
			if (!r)
				r = gnutls_certificate_allocate_credentials (&url->sc); /* docs suggest to share creds */
			if (url->cafile) {
				if (!r)
					r = gnutls_certificate_set_x509_trust_file (url->sc, url->cafile, GNUTLS_X509_FMT_PEM);
				if (r>0)
					fprintf(stderr, "%s: SSL init: loaded %zi CA certificate(s).\n", argv0, r);
				if (r>0) r = 0;
			}
			if (!r)
				gnutls_certificate_set_verify_function (url->sc, verify_certificate_callback);
			gnutls_certificate_set_verify_flags (url->sc, GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT /* suggested */
					| url->md5 | url->md2 ); /* oprional for old cert compat */
			if (!r) url->ssl_initialized = 1;
			gnutls_global_set_log_level((int)url->ssl_log_level);
			gnutls_global_set_log_function(&logfunc);
		}
		if (r) {
			ssl_error(r, url, "SSL init");
			return (sock_state) -1;
		}

		fprintf(stderr, "%s: %s: initializing SSL socket.\n", argv0, url->tname);
		r = gnutls_init(&url->ss, GNUTLS_CLIENT);
		if (!r) gnutls_session_set_ptr(url->ss, url); /* used in cert verifier */
		if (!r) r = gnutls_priority_set_direct(url->ss, ps, &errp);
		if (!r) errp = NULL;
		/* alternative to gnutls_priority_set_direct: if (!r) gnutls_set_default_priority(url->ss); */
		if (!r) r = gnutls_credentials_set(url->ss, GNUTLS_CRD_CERTIFICATE, url->sc);
		if (!r) gnutls_transport_set_ptr(url->ss, (gnutls_transport_ptr_t) (intptr_t) url->sockfd);
		if (!r) r = gnutls_handshake (url->ss);
		do ; while ((r) && handle_ssl_error(url, &r, "opening SSL socket"));
		if (r) {
			close(url->sockfd);
			if (errp) fprintf(stderr, "%s: invalid SSL priority\n %s\n %*s\n", argv0, ps, (int)(errp - ps), "^");
			fprintf(stderr, "%s: %s:%d - ", argv0, url->host, url->port);
			ssl_error(r, url, "SSL connection failed");
			fprintf(stderr, "%s: %s: closing SSL socket.\n", argv0, url->tname);
			gnutls_deinit(url->ss);
			errno = EIO;
			return (sock_state) -1;
		}
		url->ssl_connected = 1; /* Prevent printing cert data over and over again */
	}
#endif
	return url->sock_type = sock_state::SOCK_OPEN;
}

