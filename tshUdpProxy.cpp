#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
#include <vector>

#include "tshUdpProxy.h"

#define MAXLINE 1024

static std::vector<TshClient> tshList;
static FILE *gLogFile;

#define log(fmt, arg...) \
do { \
	struct tm *tm; \
	time_t t = time(NULL); \
	tm = localtime(&t); \
	if (gLogFile) { \
		fprintf(gLogFile, "%d-%02d-%02d %02d:%02d:%02d " fmt "", \
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, \
		##arg);\
		fflush(gLogFile); \
	} \
} while(0)

int createHeartBeat(uint16_t port) {
	int sockfd;
	struct sockaddr_in servaddr;

	// Creating socket file descriptor
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	
	memset(&servaddr, 0, sizeof(servaddr));
	
	// Filling server information
	servaddr.sin_family    = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(port);
	
	// Bind the socket with the server address
	if(bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

static inline std::string toIP(const struct sockaddr_in &clientAddr) {
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(clientAddr.sin_addr), str, INET_ADDRSTRLEN);
	return str;
}
static inline uint16_t toPort(const struct sockaddr_in &clientAddr) {
	return htons(clientAddr.sin_port);
}
static inline std::string toLocalTime(const time_t t) {
	char str[100];
	struct tm *tm;
	tm = localtime(&t);
	sprintf(str, "%d-%02d-%02d %02d:%02d:%02d ",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
	return str;
}

/**
 更新UDP数据包的更新时间和计数器
 */
void handleTshUdpHeartBeat(const struct sockaddr_in &srcAddr, tshProtocol &data) {
	for(TshClient &obj : tshList) {
		if (obj.isEqual(srcAddr)) {
			obj.counter++;
			obj.lastUpdate = time(NULL);
			return;
		}
	}

	TshClient newone;
	newone.clientAddr = srcAddr;
	tshList.push_back(newone);
	log("Enter " IPBLabel " %d\n", IPBValue(srcAddr), newone.counter);

	for (auto it = tshList.begin(); it != tshList.end(); ++it) {
		TshClient &obj = *it;
		if (time(NULL) - obj.lastUpdate > MAX_ALIVE_SECONDS) {
			log("Leave " IPBLabel " %d\n", IPBValue(srcAddr), obj.counter);
			tshList.erase(it);
			return;
		}
	}
}

static inline TshClient * findTshClient(uint32_t ip, uint16_t port) {
	for(TshClient &obj : tshList) {
		if (obj.isEqual(ip, port)) {
			return &obj;
		}
	}
	return NULL;
}

void handleTshUdpConnection(int udpServerSock, struct sockaddr_in &srcAddr, tshProtocol &data) {
	TshClient *targetObj = findTshClient(data.conn_ip, data.conn_port);
	
	if (targetObj) {
		struct tshProtocol senddata;
		senddata.magic = MAGIC;
		senddata.type = UPD_BACK_CONNECT;
		senddata.length = sizeof(senddata);
		senddata.listen_port = data.listen_port;
		senddata.listen_ip = data.listen_ip;

		info("Handle tsh session %d " IPBLabel " to conn [%d.%d.%d.%d:%d]\n",
			   targetObj->counter,
			   IPBValue(targetObj->clientAddr),
			   __IP3(senddata.listen_ip), __IP2(senddata.listen_ip),
			   __IP1(senddata.listen_ip), __IP0(senddata.listen_ip),
			   __PORT(senddata.listen_port)
			   );
		if(udpSendPacket(udpServerSock, &senddata, &targetObj->clientAddr)) {
			err("Error handle tsh session %d " IPBLabel " to conn [%d.%d.%d.%d:%d]\n",
				 targetObj->counter,
				 IPBValue(targetObj->clientAddr),
				 __IP3(senddata.listen_ip), __IP2(senddata.listen_ip),
				 __IP1(senddata.listen_ip), __IP0(senddata.listen_ip),
				 __PORT(senddata.listen_port)
				 );
		}
	} else {
		err("error to find connect %d.%d.%d.%d:%d\n",
			   __IP3(data.conn_ip), __IP2(data.conn_ip),
			   __IP1(data.conn_ip), __IP0(data.conn_ip),
			   __PORT(data.conn_port));
	}
}

int run(int udpServerSock) {
	struct sockaddr_in srcAddr;
	
	while (true) {
		struct tshProtocol data;
		ssize_t ret;

		ret = udpRecvPacket(udpServerSock, &data, &srcAddr);
		if (ret != sizeof(data)) {
			continue;
		}
		
		if (data.magic != MAGIC) {
			continue;
		}
		debug("udp magic from " IPBLabel " %08x type %d\n", IPBValue(srcAddr), data.magic, data.type);

		if (data.type == UPD_HEADBEAT) {
			handleTshUdpHeartBeat(srcAddr, data);
//			handleTshdTcpConnection(clientAddr);
		} else if (data.type == UPD_CONNECT) {
			handleTshUdpConnection(udpServerSock, srcAddr, data);
		}
	}
	
	return 0;
}

int main(int argc, char **argv) {
	int opt;
	const char *logfile;

	while ((opt = getopt(argc, argv, "l:")) != EOF) {
		switch(opt) {
			case 'l':
			{
				logfile = optarg;
				unlink(logfile);
				gLogFile = fopen(logfile, "a+");
				if (NULL == gLogFile) {
					log("Error to open logfile %s\n", logfile);
					exit(1);
				}
			}
		}
	}
	
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	int udpServerSock = createHeartBeat(UDP_ProxyPort);
	printf("create udp socket %d\n", udpServerSock);
	run(udpServerSock);
	return 0;
}
