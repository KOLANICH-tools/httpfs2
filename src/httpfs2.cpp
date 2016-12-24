#include "httpfs2.hpp"

#include "fuse_ops.h"

#include "Utils.hpp"

#ifdef USE_SSL
#include "TLS_Shit.h"
#endif

#include "cache.hpp"

#ifdef USE_AUTH
#include "md5.hpp"
#include "base64.hpp"
#endif


void errno_report(const char * where)
{
	struct_url * url = thread_setup();
	int e = errno;
	fprintf(stderr, "%s: %s: %s: %d %s.\n", argv0, url->tname, where, errno, strerror(errno));
	errno = e;
}

void usage(void)
{
	fprintf(stderr, "%s >>> Version: %s <<<\n", __FILE__, VERSION);
	fprintf(stderr, "usage:  %s [-c [console]] "
#ifdef USE_SSL
			"[-a file] [-d n] [-5] [-2] "
#endif
			"[-f] [-t timeout] [-r n] [-C filename] [-S n] url mount-parameters\n\n", argv0);
#ifdef USE_SSL
	fprintf(stderr, "\t -2 \tAllow RSA-MD2 server certificate\n");
	fprintf(stderr, "\t -5 \tAllow RSA-MD5 server certificate\n");
	fprintf(stderr, "\t -a \tCA file used to verify server certificate\n\t\t(default: %s)\n", CERT_STORE);
#endif
	fprintf(stderr, "\t -c \tuse console for standard input/output/error\n\t\t(default: %s)\n", CONSOLE);
#ifdef USE_SSL
	fprintf(stderr, "\t -d \tGNUTLS debug level (default 0)\n");
#endif
	fprintf(stderr, "\t -f \tstay in foreground - do not fork\n");
#ifdef RETRY_ON_RESET
	fprintf(stderr, "\t -r \tnumber of times to retry connection on reset\n\t\t(default: %i)\n", RESET_RETRIES);
#endif
	fprintf(stderr, "\t -t \tset socket timeout in seconds (default: %i)\n", TIMEOUT);
	fprintf(stderr, "\t -C \tset cache filename. also creates .idx file near to cache file\n");
	fprintf(stderr, "\t -S \tset max size of cache file (default: %lld)\n", CACHEMAXSIZE);
	fprintf(stderr, "\tmount-parameters should include the mount point\n");
}

static const char * defNumStr=" ";
int convert_num(long * num, char ** argv)
{
	char * end = const_cast<char*>(defNumStr);
	if( isdigit(*(argv[1]))) {
		*num = strtol(argv[1], &end, 0);
		/* now end should point to '\0' */
	}
	if(*end){
		usage();
		fprintf(stderr, "'%s' is not a number.\n",
				argv[1]);
		return -1;
	}
	return 0;
}

int convert_num64(unsigned long long * num, char ** argv)
{
	char * end = const_cast<char*>(defNumStr);
	if( isdigit(*(argv[1]))) {
		*num = strtoull(argv[1], &end, 0);
		/* now end should point to '\0' */
	}
	if(*end){
		usage();
		fprintf(stderr, "'%s' is not a number.\n",
				argv[1]);
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char * fork_terminal = const_cast<char*>(CONSOLE);
	char * cachename = nullptr;
	int do_fork = 1;
	const char* tzEvVarStr="TZ=";
	putenv(const_cast<char*>(tzEvVarStr));/*UTC*/
	argv0 = argv[0];
	init_url(&main_url);
	strncpy(main_url.tname, "main", TNAME_LEN);

	while( argv[1] && (*(argv[1]) == '-') )
	{
		char * arg = argv[1]; shift;
		while (*++arg){
			switch (*arg){
				case 'C': cachename = new char[strlen(argv[1])+5]; // 4 (".idx") + 1 '\0'
						  strcpy(cachename, argv[1]);
						  shift;
						  break;
				case 'S': if (convert_num64((unsigned long long*)(&cacheMaxSize), argv))
							  return 5;
						  shift;
						  break;
				case 'c': if( *(argv[1]) != '-' ) {
							  fork_terminal = argv[1]; shift;
						  }else{
							  fork_terminal = 0;
						  }
						  break;
#ifdef USE_SSL
				case '2': main_url.md2 = GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2;
						  break;
				case '5': main_url.md5 = GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5;
						  break;
				case 'a': main_url.cafile = argv[1];
						  shift;
						  break;
				case 'd': if (convert_num(&main_url.ssl_log_level, argv))
							  return 4;
						  shift;
						  break;
#endif
#ifdef RETRY_ON_RESET
				case 'r': if (convert_num(&main_url.retry_reset, argv))
							  return 4;
						  shift;
						  break;
#endif
				case 't': if (convert_num(&main_url.timeout, argv))
							  return 4;
						  shift;
						  break;
				case 'f': do_fork = 0;
						  break;
				default:
						  usage();
						  fprintf(stderr, "Unknown option '%c'.\n", *arg);
						  return 4;
			}
		}
	}

	if (argc < 3) {
		usage();
		return 1;
	}
	if (cachename) {
		if (init_cache(cachename) != 0){
			fprintf(stderr, "err cache init\n");
			 return 5;
		}
		free(cachename);
	}
	if(parse_url(argv[1], &main_url, url_flags::URL_DUP) == -1){
		fprintf(stderr, "invalid url: %s\n", argv[1]);
		return 2;
	}
	print_url(stderr, &main_url);
	sock_state sockfd = open_client_socket(&main_url);
	if((int) sockfd < 0) {
		fprintf(stderr, "Connection failed.\n");
		return 3;
	}
#ifdef USE_SSL
	else {
		print_ssl_info(main_url.ss);
	}
#endif
	close_client_socket(&main_url);
	struct stat st;
	off_t size = get_stat(&main_url, &st);
	if(size >= 0) {
		fprintf(stderr, "file size: \t%" PRIdMAX "\n", (intmax_t)size);
	}else{
		return 3;
	}

	shift;
	if(fork_terminal && access(fork_terminal, O_RDWR)){
		errno_report(fork_terminal);
		fork_terminal=0;
	}

#ifdef USE_THREAD
	close_client_force(&main_url); /* each thread should open its own socket */
	//pthread_key_create(&url_key, &destroy_url_copy);
	//pthread_mutex_init(&cache_lock, NULL);
#endif
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	char *mountpoint;
	int err = -1;
	int fork_res = 0;

	if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 &&
			(ch = fuse_mount(mountpoint, &args)) != NULL) {
		/* try to fork at some point where the setup is mostly done */
		/* FIXME try to close std* and the like ? */
		if(do_fork) fork_res = fork();

		switch (fork_res) {
			case 0:

				{
					if(fork_terminal){
						/* if we can access the console use it */
						int fd = open(fork_terminal, O_RDONLY);
						dup2(fd, 0);
						close (fd);
						fd = open(fork_terminal, O_WRONLY);
						dup2(fd, 1);
						close (fd);
						fd = open(fork_terminal, O_WRONLY|O_SYNC);
						dup2(fd, 2);
						close (fd);
					}

					struct fuse_session *se;
					se = fuse_lowlevel_new(&args, &httpfs_oper,
							sizeof(httpfs_oper), NULL);
					if (se != NULL) {
						if (fuse_set_signal_handlers(se) != -1) {
							fuse_session_add_chan(se, ch);
							err = FUSE_LOOP(se);
							fuse_remove_signal_handlers(se);
							fuse_session_remove_chan(ch);
						}
						fuse_session_destroy(se);
					}
					fuse_unmount(mountpoint, ch);
				}
				break;;
			case -1:
				errno_report("fork");
				break;;
			default:
				err = 0;
				break;;
		}
	}
	fuse_opt_free_args(&args);

#ifdef USE_THREAD
	//pthread_mutex_destroy(&cache_lock);
#endif
	if (fdcache > 0) {
		close(fdcache);
		close(fdidx);
	}

	return err ? err : 0;
}

#ifdef USE_SSL
/* handle non-fatal SSL errors */
int handle_ssl_error(struct_url *url, ssize_t * res, const char *where)
{
	/* do not handle success */
	if (!res)
		return 0;
	/*
	 * It is suggested to retry GNUTLS_E_INTERRUPTED and GNUTLS_E_AGAIN
	 * However, retrying only causes delay in practice. FIXME
	 */
	if ((*res == GNUTLS_E_INTERRUPTED) || (*res == GNUTLS_E_AGAIN))
		return 0;

	if (*res == GNUTLS_E_REHANDSHAKE) {
		fprintf(stderr, "%s: %s: %s: %zd %s.\n", argv0, url->tname, where, *res,
				"SSL rehanshake requested by server");
		if (gnutls_safe_renegotiation_status(url->ss)) {
			*res = gnutls_handshake (url->ss);
			if (*res) {
				return 0;
			}
			return 1;
		} else {
			fprintf(stderr, "%s: %s: %s: %zd %s.\n", argv0, url->tname, where, *res,
					"safe rehandshake not supported on this connection");
			return 0;
		}
	}

	if (!gnutls_error_is_fatal((int)*res)) {
		ssl_error_p(*res, url, where, "non-fatal SSL error ");
		*res = 0;
		return 1;
	}

	return 0;
}
#endif


#include "http_fs_impl.hpp"
