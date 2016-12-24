#pragma once

#define FUSE_USE_VERSION 26

#include "config.h"
#include <fuse/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <stddef.h>
#include <inttypes.h>

#include <mutex>

#ifdef USE_THREAD
#include <pthread.h>
static pthread_key_t url_key;
//pthread_mutex_t cache_lock;
static std::mutex cache_lock;
#define FUSE_LOOP fuse_session_loop_mt
#else
#define FUSE_LOOP fuse_session_loop
#endif

#ifdef USE_SSL
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif
