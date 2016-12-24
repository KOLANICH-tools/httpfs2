#pragma once
#include "dependencies.h"
#include "sock_state.hpp"
#include "url_flags.hpp"
#include "struct_url.hpp"
#include "TLS_Shit.h"

static void http_report(const char * reason, const char * method, const char * buf, size_t len)
{
	struct_url * url = thread_setup();

	fprintf(stderr, "%s: %s: %s: %s\n", argv0, url->tname, method, reason);
	fwrite(buf, len, 1, stderr);
	if(len && ( *(buf+len-1) != '\n')) fputc('\n', stderr);
}

/*
 * Scan the received header for interesting fields. Since C does not have
 * tools for working with potentially unterminated strings this is quite
 * long and ugly.
 *
 * Return the length of the header in case part of the data was
 * read with the header.
 * Content-Length means different thing whith GET and HEAD.
 */

static ssize_t parse_header(struct_url *url, const char * buf, size_t bytes, const char * method, off_t * content_length, int expect)
{
	/* FIXME check the header parser */
	int status;
	const char * ptr = buf;
	const char * end;
	int seen_accept = 0, seen_length = 0, seen_close = 0, seen_md5 = 0;

	if (bytes <= 0) {
		errno = EINVAL;
		return -1;
	}

	end = (char*)memchr(ptr, '\n', bytes);
	if(!end) {
		http_report ( "reply does not contain newline!", method, buf, 0);
		errno = EIO;
		return -1;
	}
	end = ptr;
	while(1) {
		end = (char*)memchr(end + 1, '\n', bytes - (size_t)(end - ptr));
		if(!end || ((end + 1) >= (ptr + bytes)) ) {
			http_report ("reply does not contain end of header!",
			             method, buf, bytes);
			errno = EIO;
			return -1;
		}
		if(mempref(end, "\n\r\n", bytes - (size_t)(end - ptr), 1)) break;
	}
	ssize_t header_len = (end + 3) - ptr;

	end = (char*) memchr(ptr, '\n', bytes);
	const char * http = "HTTP/1.1 ";
	if(!mempref(ptr, http, (size_t)(end - ptr), 1) || !isdigit( *(ptr + strlen(http))) ) {
		http_report ("reply does not contain status!", method, buf, (size_t)header_len);
		errno = EIO;
		return -1;
	}
	status = (int)strtol( ptr + strlen(http), (char **)&ptr, 10);
	if (status == 301 || status == 302 || status == 307 || status == 303) {
		const char * location = "Location: ";
		const char * xmd5 = "X-MD5: ";
		int seen_location = 0, seen_md5 = 0;
		char * tmp = 0;
		int res;
		ptrdiff_t llen = (ptrdiff_t) strlen(location);

		while(1) {
			ptr = end+1;
			if( !(ptr < buf + (header_len - 4))) {
				if ( !seen_md5 && !url->redirected ) url->xmd5[0] = 0; // response from main server has no X-MD5
				if ( !seen_location) {
					close_client_force(url);
					http_report("redirect did not contain a Location header!",
					            method, buf, 0);
					errno = ENOENT;
					return -1;
				}
				url->redirect_depth ++;
				if (url->redirect_depth > MAX_REDIRECTS) {
					fprintf(stderr, "%s: %s: server redirected %i times already. Giving up.", argv0, url->tname, MAX_REDIRECTS);
					errno = EIO;
					if (tmp) free(tmp);
					return -1;
				}

				if (status == 301 && url->redirect_depth == 1) { // change url permanently only if main server asked for it
					fprintf(stderr, "%s: %s: permanent redirect to %s\n", argv0, url->tname, tmp);

					res = parse_url(tmp, url, url_flags::URL_SAVE);
				} else {
					fprintf(stderr, "%s: %s: temporary redirect to %s\n", argv0, url->tname, tmp);

					url->redirected = 1;
					res = parse_url(tmp, url, url_flags::URL_DROP);
					//free(tmp);
				}
				if (tmp) free(tmp);

				if(res < 0) {
					errno = EIO;
					return res;
				}

				print_url(stderr, url);
				return -EAGAIN;
			}

			end = (char*) memchr(ptr, '\n', bytes - (size_t)(ptr - buf));
			if( mempref(ptr, xmd5, (size_t)(end - ptr), 0) ) {
				if ( ! url->redirected ) {
					strncpy(url->xmd5,(ptr + strlen(xmd5)), (size_t)(end - ptr) - strlen(xmd5)-1);
					url->xmd5[32] = 0;
					seen_md5 = 1;
				}
				fprintf(stderr,"Is in redirect?: %s\n", url->redirected?"yes":"no");
				fprintf(stderr,"X-MD5: %s\n", url->xmd5);
				continue;
			}
			if (mempref(ptr, location, (size_t)(end - ptr), 0) ) {
				size_t len = (size_t) (end - ptr - llen);
				if (*(end-1) == '\r') len--; // check for trailing '\r' and remove it
				tmp = new char[len + 1];

				tmp[len] = 0;
				strncpy(tmp, ptr + llen, len);
				seen_location = 1;
				continue;
				/*
								url->redirect_depth ++;
								if (url->redirect_depth > MAX_REDIRECTS) {
									fprintf(stderr, "%s: %s: server redirected %i times already. Giving up.", argv0, url->tname, MAX_REDIRECTS);
									errno = EIO;
									return -1;
								}

								if (status == 301 && url->redirect_depth == 1) { // change url permanently only if main server asked for it
									fprintf(stderr, "%s: %s: permanent redirect to %s\n", argv0, url->tname, tmp);

									res = parse_url(tmp, url, url_flags::URL_SAVE);
								} else {
									fprintf(stderr, "%s: %s: temporary redirect to %s\n", argv0, url->tname, tmp);

									url->redirected = 1;
									res = parse_url(tmp, url, url_flags::URL_DROP);
									free(tmp);
								}

								if(res < 0) {
									errno = EIO;
									return res;
								}

								print_url(stderr, url);
								return -EAGAIN;
				*/
			}
		}
	}
	if (status != expect) {
		fprintf(stderr, "%s: %s: failed with status: %d%.*s.\n", argv0, method, status, (int)((end - ptr) - 1), ptr);
		if (!strcmp("HEAD", method)) fwrite(buf, bytes, 1, stderr); /*DEBUG*/
		if (status == 404)
			errno = ENOENT;
		else
			errno = EIO;
		return -1;
	}

	char content_length_str[] = "Content-Length: ";
	char accept[] = "Accept-Ranges: bytes";
	char range[] = "Content-Range: bytes";
	char date[] = "Last-Modified: ";
	char close[] = "Connection: close";
	char xmd5[] = "X-MD5: ";
	struct tm tm;
	while(1) {
		ptr = end+1;
		if( !(ptr < buf + (header_len - 4))) {
			if(!seen_md5 && !url->redirected) url->xmd5[0]=0;
			if(seen_accept && seen_length) {
				if ( url->redirected ) url->sock_type = sock_state::SOCK_OPEN; // don't continue with a mirror - need to get md5 from main server
				else {
					if(url->sock_type == sock_state::SOCK_OPEN && !seen_close)
						url->sock_type = sock_state::SOCK_KEEPALIVE;
					if(url->sock_type == sock_state::SOCK_KEEPALIVE && seen_close)
						url->sock_type = sock_state::SOCK_OPEN;
				}
				return header_len;
			}
			close_client_force(url);
			errno = EIO;
			if(! seen_accept) {
				http_report("server must Accept-Range: bytes", method, buf, 0);
				return -1;
			}
			if(! seen_length) {
				http_report("reply didn't contain Content-Length!", method, buf, 0);
				return -1;
			}
			/* fallback - should not reach */
			http_report("error parsing header.", method, buf, 0);
			return -1;

		}
		end = (const char *) memchr(ptr, '\n', bytes - (size_t)(ptr - buf));

		if( mempref(ptr, xmd5, (size_t)(end - ptr), 0) ) {
			if ( !  url->redirected ) {
				strncpy(url->xmd5,(ptr + strlen(xmd5)), (size_t)(end - ptr) - strlen(xmd5)-1);
				url->xmd5[32] = 0;
			}
			fprintf(stderr,"Is in redirect?: %s\n", url->redirected?"yes":"no");
			fprintf(stderr,"X-MD5: %s\n", url->xmd5);
			continue;
		}
		if( mempref(ptr, content_length_str, (size_t)(end - ptr), 0)
			&&
			isdigit( *(ptr + strlen(content_length_str)))
		) {
			*content_length = atoll(ptr + strlen(content_length_str));
			seen_length = 1;
			continue;
		}
		if( mempref(ptr, range, (size_t)(end - ptr), 0) ) {
			seen_accept = 1;
			continue;
		}
		if( mempref(ptr, accept, (size_t)(end - ptr), 0) ) {
			seen_accept = 1;
			continue;
		}
		if( mempref(ptr, date, (size_t)(end - ptr), 0) ) {
			memset(&tm, 0, sizeof(tm));
			if(! strptime(ptr + strlen(date), "%n%a, %d %b %Y %T %Z", &tm) ) {
				http_report("invalid time", method, ptr + strlen(date), (size_t)(end - ptr) - strlen(date)) ;
				continue;
			}
			url->last_modified = mktime(&tm);
			continue;
		}
		if( mempref(ptr, close, (size_t)(end - ptr), 0) ) {
			seen_close = 1;
		}
	}
}

/*
 * Send the header, and get a reply.
 * This relies on 1k reads and writes being generally atomic -
 * - they fit into a single frame. The header should fit into that
 * and we do not need partial read handling so the exchange is simple.
 * However, broken sockets have to be handled here.
 */

static ssize_t
exchange(struct_url *url, char * buf, const char * method, off_t * content_length, off_t start, off_t end, size_t * header_length)
{
	ssize_t res;
	size_t bytes;
	int range = (end > 0);

req:
	/* Build request buffer, starting with the request method. */

	bytes = (size_t)snprintf(buf, HEADER_SIZE, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, url->path, url->host);
	bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes, "User-Agent: %s %s\r\n", __FILE__, VERSION);
	if (range) bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes, "Range: bytes=%" PRIdMAX "-%" PRIdMAX "\r\n", (intmax_t)start, (intmax_t)end);
#ifdef USE_AUTH
	if ( url->auth )
		bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes, "Authorization: Basic %s\r\n", url->auth);
#endif
	bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes, "\r\n");

	/* Now actually send it. */
	while(1) {
		/*
		 * It looks like the sockets abandoned by the server do not go away.
		 * Instead of returning EPIPE they allow zero writes and zero reads. So
		 * this is the place where a stale socket would be detected.
		 *
		 * Socket that return EAGAIN cause long delays. Reopen.
		 *
		 * Reset errno because reads/writes of 0 bytes are a success and are not
		 * required to touch it but are handled as error below.
		 *
		 */
#define CONNFAIL ((res <= 0) && ! errno) || (errno == EAGAIN) || (errno == EPIPE)

		errno = 0;
		res = write_client_socket(url, buf, bytes);

#ifdef RETRY_ON_RESET
		if ((errno == ECONNRESET) && (url->resets < url->retry_reset)) {
			errno_report("exchange: sleeping");
			sleep(1U << url->resets);
			url->resets ++;
			if (close_client_force(url) == sock_state::SOCK_EAGAIN)
				goto req;
			continue;
		}
		url->resets = 0;
#endif
		if (CONNFAIL) {
			errno_report("exchange: failed to send request, retrying"); /* DEBUG */
			if (close_client_force(url) == sock_state::SOCK_EAGAIN)
				goto req;
			continue;
		}
		if (res <= 0) {
			errno_report("exchange: failed to send request"); /* DEBUG */
			if (close_client_force(url) == sock_state::SOCK_EAGAIN)
				goto req;
			if (!errno)
				errno = EIO;
			return res;
		}
		res = read_client_socket(url, buf, HEADER_SIZE);
#ifdef RETRY_ON_RESET
		if ((errno == ECONNRESET) && (url->resets < url->retry_reset)) {
			errno_report("exchange: sleeping");
			sleep(1U << url->resets);
			url->resets ++;
			if (close_client_force(url) == sock_state::SOCK_EAGAIN)
				goto req;
			continue;
		}
		url->resets = 0;
#endif
		if (CONNFAIL) {
			errno_report("exchange: did not receive a reply, retrying"); /* DEBUG */
			if (close_client_force(url) == sock_state::SOCK_EAGAIN)
				goto req;
			continue;
		} else if (res <= 0) {
			errno_report("exchange: failed receving reply from server"); /* DEBUG */
			if (close_client_force(url) == sock_state::SOCK_EAGAIN)
				goto req;
			if (!errno)
				errno = EIO;
			return res;
		} else {
			bytes = (size_t)res;
			res = parse_header(url, buf, bytes, method, content_length, range ? 206 : 200);
			if (res == -EAGAIN) /* redirect */
				goto req;

			if (res <= 0) {
				http_report("exchange: server error", method, buf, bytes);
				return res;
			}

			if (header_length) *header_length = (size_t)res;

			return (ssize_t)bytes;
		}
	}
}

/*
 * Function uses HEAD-HTTP-Request
 * to determine the file size
 */

off_t get_stat(struct_url *url, struct stat * stbuf)
{
	char buf[HEADER_SIZE];

	if( exchange(url, buf, "HEAD", &(url->file_size), 0, 0, 0) < 0 )
		return -1;

	close_client_socket(url);

	stbuf->st_mtime = url->last_modified;
	return stbuf->st_size = url->file_size;
}


/*
 * get_data does all the magic
 * a GET-Request with Range-Header
 * allows to read arbitrary bytes
 */

ssize_t get_data(struct_url *url, off_t start, size_t rsize)
{
	char buf[HEADER_SIZE];
	char md5[33];
	const char * b;
	ssize_t bytes;
	off_t end = start + (off_t)rsize - 1;
	char * destination; //  = url->req_buf;
	off_t content_length;
	size_t header_length;
#ifdef USE_AUTH
	MD5_CTX ctx;
#endif
	unsigned char xmd5[33]; // 32 digits + null terminator
	size_t size;

	if (fdcache>0)
		if ( (bytes = (ssize_t)get_cached(url, start, rsize)) == (ssize_t)rsize ) return (ssize_t)rsize;

retry:
	destination = url->req_buf;
	size = rsize;

	bytes = exchange(url, buf, "GET", &content_length,
	                 start, end, &header_length);
	if(bytes <= 0) return -1;

	if (content_length != size) {
		http_report("didn't yield the whole piece.", "GET", 0, 0);
		size = min((size_t)content_length, size);
	}


	b = buf + header_length;

	bytes -= (b - buf);
	memcpy(destination, b, (size_t)bytes);

#ifdef USE_AUTH
	MD5_Init(&ctx);
	MD5_Update(&ctx, destination, (size_t)bytes);
#endif

	size -= (size_t)bytes;
	destination +=bytes;
	for (; size > 0; size -= (size_t)bytes, destination += bytes) {

		bytes = read_client_socket(url, destination, size);
		if (bytes < 0) {
			errno_report("GET (read)");
			return -1;
		}
		if (bytes == 0) {
			break;
		}
		MD5_Update(&ctx, destination, (size_t)bytes);
	}

	MD5_Final(xmd5,&ctx);
#if 1
	{
		int i;
		for(i = 0; i < 16; i++) sprintf((char*)(md5+(i<<1)), "%02x", xmd5[i]);
		md5[32]=0;
		fprintf(stderr, "XMD5 : %s\n",(char*)url->xmd5);
		fprintf(stderr, "MD5  : %s\n",md5);
		if (strncmp((char*)url->xmd5, (char*)md5, 32) && url->xmd5[0]) {
			close_client_force(url);
			goto retry;
		}
	}
#endif
	close_client_socket(url);
	if (fdcache>0) {
		update_cache(url, start, rsize, md5);
	}
	return (ssize_t)(end - start) + 1 - (ssize_t)size;
}
