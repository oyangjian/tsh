#ifndef _TSH_H
#define _TSH_H

#ifndef SECRET_PASSWD
#define SECRET_PASSWD "123456"
#endif
char *secret = SECRET_PASSWD;
char *cb_host = NULL;

#define SERVER_PORT 1234
short int server_port = SERVER_PORT;
const char *server_hostname;

#define CONNECT_BACK_HOST  "localhost"
#define CONNECT_BACK_DELAY 5

#ifndef MAX_UDP_HEARTBEAT
#define MAX_UDP_HEARTBEAT (1 * 60)
#endif

#define GET_FILE 1
#define PUT_FILE 2
#define RUNSHELL 3

#endif /* tsh.h */
