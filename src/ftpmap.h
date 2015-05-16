
/* ftpmap.h - the FTP-Map project header */

#include <stdio.h>

#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
# include <stdarg.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#else
# if HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <time.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#elif defined(HAVE_SYS_FCNTL_H)
# include <sys/fcntl.h>
#endif

#ifdef HAVE_IOCTL_H
# include <ioctl.h>
#elif defined(HAVE_SYS_IOCTL_H)
# include <sys/ioctl.h>
#endif

#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef HAVE_ALLOCA
# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# endif

# define ALLOCA(X) alloca(X)
# define ALLOCA_FREE(X) do { } while (0)
#else
# define ALLOCA(X) malloc(X)
# define ALLOCA_FREE(X) free(X)
#endif

#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0
#endif

#ifndef errno
extern int errno;
#endif

#ifdef TCP_CORK
# define CORK_ON(SK) do { int optval = 1; setsockopt(SK, SOL_TCP, TCP_CORK, \
  &optval, sizeof optval); } while(0)
# define CORK_OFF(SK) do { int optval = 0; setsockopt(SK, SOL_TCP, TCP_CORK, \
  &optval, sizeof optval); } while(0)
#else
# define CORK_ON(SK) do { } while(0)
# define CORK_OFF(SK) do { } while(0)
#endif

#define STORAGE_PORT(X) (((struct sockaddr_in *) &(X))->sin_port)
#define STORAGE_PORT6(X) (((struct sockaddr_in6 *) &(X))->sin6_port)
#define STORAGE_SIN_ADDR(X) ((((struct sockaddr_in *) &(X))->sin_addr).s_addr)
#define STORAGE_SIN_ADDR6(X) ((((struct sockaddr_in6 *) &(X))->sin6_addr).s6_addr)
#define STORAGE_SIN_ADDR6_NF(X) (((struct sockaddr_in6 *) &(X))->sin6_addr)

#ifdef HAVE_SS_LEN
# define STORAGE_LEN(X) ((X).ss_len)
# define SET_STORAGE_LEN(X, Y) do { STORAGE_LEN(X) = (Y); } while(0)
#elif defined(HAVE___SS_LEN)
# define STORAGE_LEN(X) ((X).__ss_len)
# define SET_STORAGE_LEN(X, Y) do { STORAGE_LEN(X) = (Y); } while(0)
#else
# define STORAGE_LEN(X) (STORAGE_FAMILY(X) == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
# define SET_STORAGE_LEN(X, Y) (void) 0
#endif

#ifdef HAVE___SS_FAMILY
# define STORAGE_FAMILY(X) ((X).__ss_family)
#else
# define STORAGE_FAMILY(X) ((X).ss_family)
#endif

#ifndef SOL_IP
# define SOL_IP IPPROTO_IP
#endif
#ifndef SOL_TCP
# define SOL_TCP IPPROTO_TCP
#endif

#ifndef INADDR_NONE
# define INADDR_NONE 0
#endif

#if !defined(O_NDELAY) && defined(O_NONBLOCK)
# define O_NDELAY O_NONBLOCK
#endif

#ifndef FNDELAY
# define FNDELAY O_NDELAY
#endif

#ifdef WITH_DMALLOC
# define _exit(X) exit(X)
#endif

#define MAX_STR 256
#define MAX_ANSWER  1024
#define FTP_CRLF    "\x0a\x0d"
#define FTP_DEFAULT_SERVER  "localhost"
#define FTP_DEFAULT_PORT    "21"
#define FTP_DEFAULT_USER    "Anonymous"
#define FTP_DEFAULT_PASSWORD    "hello@world"

int fd;

typedef struct {
    FILE *fid;
    char ip_addr[MAX_STR];
    char software[MAX_STR];
    char sversion[MAX_STR];
    char fingerprint_software[MAX_STR];
    char *answer;
    char *server;
    char *port;
    char *user;
    char *password;
 } ftpmap_t;

void ftpmap_detect_version_by_banner(ftpmap_t*);
void ftpmap_init(ftpmap_t*);
void ftpmap_reconnect(ftpmap_t*, int);
void print_usage(int);
void print_version(int);
void sigalrm(int);

