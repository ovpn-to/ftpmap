
/* (C)opyleft 2001-2002 by Jedi/Sector One <j@4u.net> */

#include "ftpmap.h"
#include "testcmds.h"
#include "fingerprints.h"

const char *ftp_server;
const char *ftp_port = FTP_DEFAULT_PORT; 
const char *ftp_user = FTP_DEFAULT_USER;
const char *ftp_pass = FTP_DEFAULT_PASS;
signed char debug;
int kindy = -1;

static void reconnect(struct addrinfo *res_scan_, FILE **fp, int login_);

RETSIGTYPE sigalrm(int dummy)
{
    (void) dummy;
    close(kindy);
    kindy = -1;
}

static char *getftpanswer(FILE **fp)
{
    static char answer[FTP_ANSWER_MAX];
    char *s;    
    
    signal(SIGALRM, sigalrm);
    alarm(5);
    *answer = 0;
    while (fgets(answer, sizeof answer, *fp) != NULL) {
        if (strtol(answer, &s, 10) != 0 && s != NULL) {
            if (isspace(*s)) {
                if (debug != 0) {
                    printf("*DEBUG* <-- %s", answer);
                }
                return answer;
            }
        }
    }
    if (*answer == 0) {        
        reconnect(NULL, fp, -1);
    }
    if (debug != 0) {
        printf("*DEBUG* <-- %s\n", answer);
    }
    return answer;
}

static int banner(FILE ** const fp)
{
    char *answer;
    
    answer = getftpanswer(fp);
    if (answer == NULL) {
        reconnect(NULL, fp, -1);
    }        
    return 0;    
}

static int dologin(FILE ** const fp,
                   const char * const login, const char * const pass)
{
    char *answer;
    
    fprintf(*fp, "USER %s" FTP_CRLF, login);
    answer = getftpanswer(fp);
    if (answer == NULL) {
        reconnect(NULL, fp, -1);
        return 0;
    }
    if (*answer == '2') {
        return 0;
    }
    fprintf(*fp, "PASS %s" FTP_CRLF, pass);
    answer = getftpanswer(fp);
    if (answer == NULL) {
        reconnect(NULL, fp, -1);
        return 0;
    }    
    if (*answer == '2') {        
        return 0;
    }
    return -1;
}

static void reconnect(struct addrinfo *res_scan_, FILE **fp, int login_)
{
    static struct addrinfo res_scan;
    static int login;
    static signed char recurse;
        
    if (debug != 0) {
        puts("*DEBUG* reconnect");
    }
    if (kindy >= 0) {
        fclose(*fp);
        close(kindy);
        kindy = -1;
    }
    if (res_scan_ != NULL) {
        res_scan = *res_scan_;
    }
    if (login_ >= 0) {
        login = login_;
    }
    if ((kindy = socket(res_scan.ai_family, res_scan.ai_socktype,
                        res_scan.ai_protocol)) < 0) {
        perror("Sorry, I'm unable to create a new socket");
        exit(EXIT_FAILURE);
    }
    if (connect(kindy, res_scan.ai_addr, res_scan.ai_addrlen) < 0) {
        perror("Sorry, I'm unable to connect");
        exit(EXIT_FAILURE);
    }
    *fp = fdopen(kindy, "r+");
    if (*fp == NULL) {
        return;
    }
    if (recurse != 0) {
	return;
    }    
    recurse = 1;
    banner(fp);
    if (login != 0) {
        dologin(fp, ftp_user, ftp_pass);
    }
    recurse = 0;
}

static unsigned long checksum(const char *s)
{
    unsigned long checksum = 0UL;

    while (*s != 0) {
        checksum += (unsigned char) *s++;
    }
    return checksum;
}

static int updatestats(const unsigned long sum, int testnb)
{
    FP *f = fingerprints;
    int nf = sizeof fingerprints / sizeof fingerprints[0];
    long long err;
    
    do {
        err = (signed long long) f->testcase[testnb] - (signed long long) sum;
        if (err < 0LL) {
            err = -err;
        }
        if (err > 0LL) {
            f->err += (unsigned long) err;
        }
        f++;
        nf--;
    } while (nf != 0);
    return 0;
}

static const char * seqidx2difficultystr(const unsigned long long idx)
{
    return  (idx < 100ULL)? "Trivial joke" : (idx < 1000ULL)? "Easy" : (idx < 4000ULL)? "Medium" : (idx < 8000ULL)? "Formidable" : (idx < 16000ULL)? "Worthy challenge" : "Good luck!";
}

static int findseq(FILE ** const fp)
{
    char *answer;
    int a, b, c, d, e, f;
    unsigned int port[5];
    unsigned int rndports[10000];
    int n = 0;
    unsigned long long dif = 0ULL;
    long portdif;
    int timedep = 0;
            
    srand(time(NULL));
    do {
        rndports[n] = 1024 + 
            (int) ((1.0 * (65536 - 1024) * rand()) / (RAND_MAX + 1.0));
        n++;
    } while (n < (sizeof rndports / sizeof rndports[0]));
    
    n = 0;
    do {
        fprintf(*fp, "PASV" FTP_CRLF);
        answer = getftpanswer(fp);
        if (*answer != '2') {
            noseq:                        
            puts("*** Unable to determine FTP port sequence numbers");
            return -1;
        }
        while (*answer != 0 && *answer != '(') {
            answer++;
        }
        if (*answer != '(') {
            goto noseq;
        }
        answer++;    
        if (sscanf(answer, "%u,%u,%u,%u,%u,%u", &a, &b, &c, &d, &e, &f) < 6) {
            goto noseq;
        }
        port[n] = e * 256U + f;
        n++;
    } while (n < (sizeof port / sizeof port[0]));
    printf("*** FTP port sequence numbers : ");
    n = 0;
    do {
        printf("%u ", port[n]);
        if (n != 0) {
            portdif = (long) port[n] - (long) port[n - 1];
            if (portdif < 0L) {
                portdif = -portdif;
            }
            dif += (unsigned long long) portdif;        
        }
        {
            int n2 = 0;
            
            do {
                if (rndports[n2] == port[n]) {
                    timedep++;
                    break;
                }
                n2++;
            } while (n2 < (sizeof rndports / sizeof rndports[0]));
        }        
        n++;
    } while (n < (sizeof port / sizeof port[0]));
    if (timedep > 2) {
        printf("\n    *** POSSIBLE TRIVIAL TIME DEPENDENCY - INSECURE ***");
    }
    dif /= (sizeof port / sizeof port[0] - 1);
    printf("\n    Difficulty = %llu (%s)\n\n", dif, seqidx2difficultystr(dif));
    return 0;
}

static int fingerprint(FILE ** const fp)
{
    char *answer;
    const char **cmd;
    unsigned long sum;
    int testnb = 0;
    
    cmd = testcmds;
    while (*cmd != NULL) {
        if (debug != 0) {
            printf("*DEBUG* --> %s", *cmd);
        }
        fprintf(*fp, "%s", *cmd);
        fflush(*fp);
        answer = getftpanswer(fp);
        if (answer == NULL) {
            sum = 0UL;
        } else {
            sum = checksum(answer);
        }
        if (debug == 0) {
            printf("%lu,", sum);
        }
        fflush(stdout);
        updatestats(sum, testnb);
        testnb++;                    
        cmd++;
    }
    puts("");
    return 0;
}

static int compar(const void *a_, const void *b_)
{
    const FP *a = (const FP *) a_;
    const FP *b = (const FP *) b_;
    
    if (a->err != b->err) {
        return a->err - b->err;
    }
    return strcasecmp(b->software, a->software);
}

static int findwinner(void)
{
    FP *f = fingerprints;
    int nb = sizeof fingerprints / sizeof fingerprints[0];
    int nrep = 0;
    double maxerr;
    const char *olds = NULL;
    
    qsort(fingerprints, sizeof fingerprints / sizeof fingerprints[0],
          sizeof fingerprints[0], compar);
    maxerr = (double) fingerprints[nb - 1].err;
    puts("\n*** This may be running :");
    do {        
        if (olds == NULL || strcasecmp(olds, f->software) != 0) {
            olds = f->software;
            printf("[%s]\t(error=%g %%)\n", f->software,
                   ((double) f->err * 100.0) / maxerr);
            nrep++;            
        }
        if (nrep > 2) {
            break;
        }
        f++;
        nb--;
    } while (nb != 0);
    puts("");
    
    return 0;    
}

static int scan(const char * const host, const char * const port)
{
	int ret;
    int rtn = 0;
	struct addrinfo ai, *res, *res_scan;
	char *answer;
    FILE *fp;

	memset(&ai, 0, sizeof ai);
	ai.ai_family = AF_UNSPEC;
	ai.ai_protocol = IPPROTO_TCP;
	ai.ai_socktype= SOCK_STREAM;
	if ((ret = getaddrinfo(host, port, &ai, &res)) != 0) {
		fprintf(stderr, "[%s]\n", gai_strerror(ret));
		return -1;
	}	
	res_scan = res;
	while (res_scan != NULL) {
        
        {
            char hbuf[NI_MAXHOST];
            
            getnameinfo((struct sockaddr *) res_scan->ai_addr, res_scan->ai_addrlen,
                        hbuf, sizeof hbuf, NULL, (size_t) 0U, NI_NUMERICHOST);
            printf("*** Scanning IP : [%s]\n\n*** Fingerprint :\n\n", hbuf);
        }
        
        reconnect(res_scan, &fp, 0);
        fingerprint(&fp);
        reconnect(res_scan, &fp, 1);
        fingerprint(&fp);
        findwinner();
        reconnect(res_scan, &fp, 1);
        findseq(&fp);
		res_scan = res_scan->ai_next;        
    }
    freeaddrinfo(res);
    return rtn;            
}

static void help(void)
{
	puts("FTP-Map " VERSION "\n\n"
         "Usage : ftpmap [-h] [-P <port>] [-u <login>] [-p <pass>] -s <host>\n\n"
         "-h         : help\n"
         "-P <port>  : connect to port <port> (default=" FTP_DEFAULT_PORT ")\n"
         "-u <login> : login to the server as <login> (default=" FTP_DEFAULT_USER ")\n"
         "-p <pass>  : use this password (default=" FTP_DEFAULT_PASS ")\n"                                                                                          
		 "-s <host>  : connect to FTP server running on <host> (IP or name)\n");
	exit(EXIT_FAILURE);
}

static void parseoptions(int nbargs, char *args[])
{
	int fodder;
	
	while ((fodder = getopt(nbargs, args, "dhs:P:u:p:")) != -1) {
		switch(fodder) {
        case 'd':
            debug = 1;
            break;
		case 'h':
			help();
        case 's':
            ftp_server = strdup(optarg);
            break;
        case 'P':
            ftp_port = strdup(optarg);
            break;
        case 'p':
            ftp_pass = strdup(optarg);
            break;
        case 'u':
            ftp_user = strdup(optarg);
            break;
        default:
            help();
		}
	}
}

int main(int nbargs, char *args[])
{
	parseoptions(nbargs, args);
    if (ftp_server == NULL) {        
        puts("Please tell me what server has to be probed (-s <host>)\n");
        help();
    }
    if (scan(ftp_server, ftp_port) != 0) {
		perror("Error during the scan");
        return -1;
    }
    puts("\nIf you know the name of the FTP server you just scanned, please\n"
         "contribute to this program by sending the fingerprint and the\n"
         "name of the server software to : ftpmap@pureftpd.org\n");
	
	return 0;
}

