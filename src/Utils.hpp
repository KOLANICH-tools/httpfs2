#pragma once
#include "dependencies.h"
/*
 * A few utility functions
 */
#ifdef NEED_STRNDUP
static char * strndup(const char * str, size_t n);
#endif

int mempref(const char * mem, const char * pref, size_t size, int case_sensitive);

char * url_encode(char * path);

#define shift { if(!argv[1] || !argv[2]) { usage(); return 4; };\
	argc--; argv[1] = argv[0]; argv = argv + 1;}

