/*  ftpmap.c - the FTP-Map project
 
  Copyleft 2015 by Hypsurus <hypsurus@mail.ru> 
  Copyleft 2001-2002 by Jedi/Sector One <j@4u.net> 

*/
/*
  FTP-Map is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  FTP-Map is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "ftpmap.h"
#include "testcmds.h"
#include "fingerprints.h"

void ftpmap_init(ftpmap_t *ftpmap) {
    ftpmap->port   = strdup(FTP_DEFAULT_PORT);
    ftpmap->user = strdup(FTP_DEFAULT_USER);
    ftpmap->password = strdup(FTP_DEFAULT_PASSWORD);
}

void die(int stat, char *format, ...) {
        va_list li;
        char m[MAX_STR];

        va_start(li, format);
        vsnprintf(m, sizeof(m), format, li);
        va_end(li);

        if ( stat == 1 ) {
            fprintf(stderr, "[ERROR] Oh No! %s\n", m);
            exit(EXIT_FAILURE);
        }

        if ( stat == 2 ) {
            fprintf(stderr, "[Debug] %s\n", m);
        }
}

void * xmalloc(size_t size) {
    void *ret = malloc(size);

    if ( !ret && size )
        die(1, "Failed to allocate: %zu bytes.", size);

    return ret;
}

void print_version(int ex) {
    printf("FTP-Map %s\n", VERSION);
    exit(ex);
}

void print_usage(int ex) {
    printf("Usage: ftpmap -s [host] [OPTIONS]...\n\n"
          "Options:\n"
          "\t-s <host>     : the FTP server.\n"
          "\t-p <port>     : the FTP port (default: 21).\n"
          "\t-U <user>     : FTP user (defulat: anonymous).\n"
          "\t-P <password> : FTP password (default: hello@world). \n"
          "\t-v            : show version information and quit.\n"
          "\t-h            : show helo and quit.\n"
          "\nPlease send bugs report/help to hypsurus@mail.ru\n"
          "License GPLv2: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>.\n");
    exit(ex);
}

void print_startup(ftpmap_t *ftpmap) {
    printf("Starting FTP-Map %s - Scanning (%s:%s)...\n\n", VERSION, ftpmap->ip_addr, ftpmap->port);
}

void sigalrm(int dummy) {
    (void) dummy;
    close(fd);
    fd = -1;
}

char * ftpmap_getanswer(ftpmap_t *ftpmap) {
    static char answer[MAX_ANSWER];
    char *s = NULL;    

    *answer = 0;

    signal(SIGALRM, sigalrm);
    alarm(5);
    while (fgets(answer, sizeof answer, ftpmap->fid) != NULL) {
        if (strtol(answer, &s, 10) != 0 && s != NULL) {
            if (isspace(*s)) {
                return answer;
            }
        }
    }
    if (*answer == 0) {        
        ftpmap_reconnect(ftpmap,0);
    }

    return answer;
}

void ftpmap_detect_version_by_banner(ftpmap_t *ftpmap) {
    FILE *fp;
    char vv[MAX_STR];
    char v[MAX_STR];
    
    sprintf(v, "%s%s", ftpmap->software, ftpmap->sversion);
    printf("\t[INFO] Trying to detect FTP server by banner...\n");

    if (( fp = fopen("../db/ftp-versions-db", "r")) == NULL )
        die(1, "Failed to open ftp-versions-db file, The file exists?");

    while (( fgets(vv, sizeof(vv), fp)) != NULL ) {
        strtok(vv, "\n");
        if (strcasecmp(vv, v) == 0) {
            printf("\t[*] Found FTP Version: %s\n", vv);
            break;
        }
    }
}

int ftpmap_login(ftpmap_t *ftpmap) {
    char version[MAX_STR];

    print_startup(ftpmap);
    ftpmap->answer = ftpmap_getanswer(ftpmap);
    printf("\t[*] FTP Banner: %s", ftpmap->answer);

    sscanf(ftpmap->answer, "220 %s %s", ftpmap->software, ftpmap->sversion);

    fprintf(ftpmap->fid, "USER %s\x0a\x0d", ftpmap->user);
    ftpmap->answer = ftpmap_getanswer(ftpmap);

    if ( ftpmap->answer == 0 )
        ftpmap_reconnect(ftpmap, 0);

    if ( *ftpmap->answer == '2' )
        return 0;
    
    fprintf(ftpmap->fid, "PASS %s\x0a\x0d", ftpmap->password);
    ftpmap->answer = ftpmap_getanswer(ftpmap);  

    if ( ftpmap->answer == 0 )
        ftpmap_reconnect(ftpmap, 0);

    if ( *ftpmap->answer == '2' ) {
        printf("\t[+} FTP Anonymous login Allowed !\n");
        return 0;
    }

    printf("\t[*] FTP Anonymous login NOT Allowed !\n");
    return -1;
}

void ftpmap_findexploit(ftpmap_t *ftpmap) {
    FILE *fp;
    int id = 0, exploit_counter = 0;
    char exploit[MAX_STR];
    char line[MAX_STR];
    char fsoftware[MAX_STR], fsversion[MAX_STR];

    sscanf(ftpmap->fingerprint_software, "%s %s", &fsoftware, &fsversion);

    if (( fp = fopen("../db/ftp-exploit-db", "r")) == NULL )
        die(1, "Failed to open the ftp-exploit-db file.");

    printf("\n\t[*] Searching explolits...\n");
    while (( fgets(line, sizeof(line), fp)) != NULL ) {
        sscanf(line, "%d,%[^\n]s", &id, &exploit);
        if ( strcasestr(exploit, ftpmap->software) && strstr(exploit, ftpmap->sversion)) {
            printf("\t[+] Exploit: %s\n"
                    "\t[*] Download: http://exploit-db.com/download/%d\n", exploit, id);
            exploit_counter++;
        }
        else if ( strcasestr(exploit, fsoftware) && strstr(exploit, fsversion)) {
            printf("\t[+] Exploit: %s\n"
                   "\t[*] Download: http://exploit-db.com/download/%d\n", exploit, id);
            exploit_counter++;

        }
    }

    if ( exploit_counter == 0 )
        printf("\t[INFO] FTP-Map didn't find any exploits in exploit-db.com\n");
}

int ftpmap_updatestats(const unsigned long sum, int testnb) {
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

const char * seqidx2difficultystr(const unsigned long long idx) {
    return  (idx < 100ULL)? "Trivial joke" : (idx < 1000ULL)? "Easy" : (idx < 4000ULL)? "Medium" : (idx < 8000ULL)? "Formidable" : (idx < 16000ULL)? "Worthy challenge" : "Good luck!";
}

int ftpmap_findseq(ftpmap_t *ftpmap) {
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
        fprintf(ftpmap->fid, "PASV" FTP_CRLF);
        answer = ftpmap_getanswer(ftpmap);
        if (*answer != '2') {
            noseq:                        
            printf("\t[INFO] Unable to determine FTP port sequence numbers\n");
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
    printf("\t[*] FTP port sequence numbers : ");
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
        printf("\t*** POSSIBLE TRIVIAL TIME DEPENDENCY - INSECURE ***\n");
    }
    dif /= (sizeof port / sizeof port[0] - 1);
    printf("\n\tDifficulty = %llu (%s)\n\n", dif, seqidx2difficultystr(dif));
    return 0;
}

int ftpmap_compar(const void *a_, const void *b_) {
    const FP *a = (const FP *) a_;
    const FP *b = (const FP *) b_;
    
    if (a->err != b->err) {
        return a->err - b->err;
    }
    return strcasecmp(b->software, a->software);
}

int ftpmap_findwinner(ftpmap_t *ftpmap) {
    FP *f = fingerprints;
    int nb = sizeof fingerprints / sizeof fingerprints[0];
    int nrep = 0;
    double maxerr;
    const char *olds = NULL;

    printf("\t[INFO] This may be running :\n");
    qsort(fingerprints, sizeof fingerprints / sizeof fingerprints[0],
          sizeof fingerprints[0], ftpmap_compar);
    maxerr = (double) fingerprints[nb - 1].err;
    do {        
        if (olds == NULL || strcasecmp(olds, f->software) != 0) {
            olds = f->software;
            printf("\t\t[%s]\t(error=%g %%)\n", f->software,
                   ((double) f->err * 100.0) / maxerr);
            nrep++;            
        }
        if ( nrep == 1 )
            sprintf(ftpmap->fingerprint_software, "%s", f->software);
        if (nrep > 2) {
            break;
        }
        f++;
        nb--;
    } while (nb != 0);
    
    putchar(0x0a);
    return 0;    
}

unsigned long ftpmap_checksum(const char *s) {
    unsigned long checksum = 0UL;

    while (*s != 0) {
        checksum += (unsigned char) *s++;
    }
    return checksum;
}

int ftpmap_fingerprint(ftpmap_t *ftpmap) {
    char *answer = NULL;
    const char **cmd;
    unsigned long sum;
    int testnb = 0;
    int progress = 0;
    int max = 0;
    FILE *fp;
    char filename[MAX_STR];

    sprintf(filename, "%s-fingerprint.log", ftpmap->ip_addr);

    if (( fp = fopen(filename, "w+")) == NULL )
        die(1, "Failed to write fingerprint log file.");

    printf("\t[INFO] Trying to detect FTP server by fingerprint...\n");
    cmd = testcmds;
    max = 141;

    fprintf(fp, "# Generated by FTP-Map\n# Please send this fingerprint to hypsurus@mail.ru with the name of the server and version.\n\n\n# Fingerprint:\n\n");

    while (*cmd != NULL) {
        fprintf(ftpmap->fid, "%s", *cmd);
        fflush(ftpmap->fid);
        answer = ftpmap_getanswer(ftpmap);
        if (answer == NULL) {
            sum = 0UL;
        } else {
            sum = ftpmap_checksum(answer);
        }

        printf("\t[INFO] Generating fingerprint [%d%%]\r", progress * 100 / max );
        fprintf(fp, "%lu,", sum);
        fflush(stdout);
        ftpmap_updatestats(sum, testnb);
        testnb++;                    
        cmd++;
        progress++;
    }
    printf("\t[*] Fingerprint saved: %s\n", filename);
    fclose(fp);
    putchar(0x0a);
    return 0;
}

void ftpmap_reconnect(ftpmap_t *ftpmap, int login) {
    struct addrinfo ai, *srv = NULL, *p = NULL;
    struct sockaddr_in c;
    char hbuf[MAX_STR];

    memset(&ai, 0, sizeof(ai));

    /* ai.ai_family = AF_UNSPEC */
    ai.ai_family = AF_INET;
    ai.ai_protocol = IPPROTO_TCP;
    ai.ai_socktype = SOCK_STREAM;

    if (( getaddrinfo(ftpmap->server, ftpmap->port, &ai, &srv)) != 0 ) 
        die(1, "Connection failed.");

    p = srv;

    getnameinfo((struct sockaddr *) p->ai_addr, p->ai_addrlen,
                        hbuf, sizeof hbuf, NULL, (size_t) 0U, NI_NUMERICHOST);

    sprintf(ftpmap->ip_addr, "%s", hbuf);

    if (( fd = socket(ai.ai_family, ai.ai_socktype, 
                    ai.ai_protocol)) < 0 )
        die(1, "Failed to create a new socket.");

    if ( connect(fd, p->ai_addr, p->ai_addrlen) < 0 )
        die(1, "Failed to connect");


    ftpmap->fid = fdopen(fd, "r+");
    ;
    if ( login )
        ftpmap_login(ftpmap);

    freeaddrinfo(srv);
}

int main(int argc, char **argv) {
    int opt = 0;
    ftpmap_t *ftpmap = xmalloc(sizeof (*ftpmap));

    ftpmap_init(ftpmap);
    while (( opt = getopt(argc, argv, "s:p:U:P:hv")) != -1 ) {
            switch(opt) {
                case 's':
                        ftpmap->server = strdup(optarg);
                        break;
                case 'p':
                        ftpmap->port = strdup(optarg);
                case 'U':
                        ftpmap->user = strdup(optarg);
                        break;
                case 'P':
                        ftpmap->password = strdup(optarg);
                case 'h':
                        print_usage(0);
                case 'v':
                        print_version(0);
                default:
                        print_usage(0);
             }
        }

    if ( ftpmap->server == NULL ) {
        printf("Error: Please tell me what server has to be probed (-s <host>)\n\n");
        print_usage(1);
    }

    ftpmap_reconnect(ftpmap, 1);
    ftpmap_detect_version_by_banner(ftpmap);
    ftpmap_fingerprint(ftpmap);
    ftpmap_findwinner(ftpmap);
    ftpmap_findseq(ftpmap);
    ftpmap_findexploit(ftpmap);

    printf("\nPlease send the fingerprint to hypsurus@mail.ru to improve FTP-Map.\n");
    fclose(ftpmap->fid);
    free(ftpmap);
    
    return 0;
}

