#pragma once
/*
 * HTTPFS: import a file from a web server to local file system
 * the main use is, to mount an iso on a web server with loop device
 *
 * depends on:
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *
 * This program can be distributed under the terms of the GNU GPL.
 *
 */

/*
 * (c) 2006  hmb  marionraven at users.sourceforge.net
 *
 */

/*
 * Modified to work with fuse 2.7.
 * Added keepalive
 * The passthru functionality removed to simplify the code.
 * (c) 2008-2012,2016 Michal Suchanek <hramrach@gmail.com>
 *
 */

#include "dependencies.h"

/*
 * ECONNRESET happens with some dodgy servers so may need to handle that.
 * Allow for building without ECONNRESET in case it is not defined.
 */
#ifdef ECONNRESET
#define RETRY_ON_RESET
#endif

#include "sock_state.hpp"
#include "url_flags.hpp"

struct struct_url;
static char* argv0;

off_t get_stat(struct_url*, struct stat * stbuf);
ssize_t get_data(struct_url*, off_t start, size_t rsize);
sock_state open_client_socket(struct_url *url);
sock_state close_client_socket(struct_url *url);
sock_state close_client_force(struct_url *url);
struct_url * thread_setup(void);
void destroy_url_copy(void *);

/* Protocol symbols. */
#define PROTO_HTTP 0
#ifdef USE_SSL
#define PROTO_HTTPS 1
#endif

int handle_ssl_error(struct_url *url, ssize_t * res, const char *where);

