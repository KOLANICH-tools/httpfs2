#include "Utils.hpp"
/*
 * A few utility functions
 */
#ifdef NEED_STRNDUP
static char * strndup(const char * str, size_t n){
	if(n > strlen(str)) n = strlen(str);
	char * res = malloc(n + 1);
	memcpy(res, str, n);
	res[n] = 0;
	return res;
}
#endif

int mempref(const char * mem, const char * pref, size_t size, int case_sensitive)
{
	/* return true if found */
	if (size < strlen(pref)) return 0;
	if (case_sensitive)
		return ! memcmp(mem, pref, strlen(pref));
	else {
		int i;
		for (i = 0; i < strlen(pref); i++)
			/* Unless somebody calling setlocale() behind our back locale should be C.  */
			/* It is important to not uppercase in languages like Turkish.  */
			if (tolower(mem[i]) != tolower(pref[i]))
				return 0;
		return 1;
	}
}

char * url_encode(char * path) {
	return strdup(path); /*FIXME encode*/
}
