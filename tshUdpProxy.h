#ifndef __TSH_UDP_SERVER_H__
#define __TSH_UDP_SERVER_H__ 1

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>

#define MAGIC 0xFEADDEAF
#define UPD_HEADBEAT 0x01
#define UPD_TSH_CONNECT 0x02
#define UPD_BACK_CONNECT 0x03
#define UPD_PAYLOAD_DATA 0x80

#ifndef UDP_ProxyPort
#define UDP_ProxyPort 18080
#endif

#define __PORT(sin_port) htons(sin_port)
#define __IP3(s_addr) ((htonl(s_addr) >> 24) & 0xFF)
#define __IP2(s_addr) ((htonl(s_addr) >> 16) & 0xFF)
#define __IP1(s_addr) ((htonl(s_addr) >> 8) & 0xFF)
#define __IP0(s_addr) ((htonl(s_addr) >> 0) & 0xFF)

#define _PORT(sin_port) htons(sin_port)
#define _IP3(sin_addr) ((htonl(sin_addr.s_addr) >> 24) & 0xFF)
#define _IP2(sin_addr) ((htonl(sin_addr.s_addr) >> 16) & 0xFF)
#define _IP1(sin_addr) ((htonl(sin_addr.s_addr) >> 8) & 0xFF)
#define _IP0(sin_addr) ((htonl(sin_addr.s_addr) >> 0) & 0xFF)

#define PORT(addr_in) _PORT((addr_in).sin_port)
#define IP3(addr_in) _IP3((addr_in).sin_addr)
#define IP2(addr_in) _IP2((addr_in).sin_addr)
#define IP1(addr_in) _IP1((addr_in).sin_addr)
#define IP0(addr_in) _IP0((addr_in).sin_addr)

#define IPLabel "[%d.%d.%d.%d]"
#define IPValue(addr_in) IP3(addr_in), IP2(addr_in), IP1(addr_in), IP0(addr_in)

#define IPBLabel "[%d.%d.%d.%d:%d]"
#define IPBValue(addr_in) IP3(addr_in), IP2(addr_in), IP1(addr_in), IP0(addr_in), PORT(addr_in)

#ifdef RELEASE
#define debug(a...) do { } while(0)
#define info(a...) do { } while(0)
#define err(a...) do { } while(0)
#else
#define debug logpr
#define info logpr
#define err logpr
#endif
extern int gVerbose;
static inline void logpr(const char *fmt, ...) {
	char tmp[512];

	struct tm *tm;
	time_t t = time(NULL);
	tm = localtime(&t);
	fprintf(stdout, "%d-%02d-%02d %02d:%02d:%02d ", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

	va_list al;
	va_start(al, fmt);
	int len = vsnprintf(tmp, 512, fmt, al);
	va_end(al);

	if (len > 511) {
		char *destbuff = (char *)malloc(len + 1);
		va_start(al, fmt);
		len = vsnprintf(destbuff, len + 1, fmt, al);
		va_end(al);
		fprintf(stdout, "%s", destbuff);
		free((void *)destbuff);
	} else {
		fprintf(stdout, "%s", tmp);
	}
}

/**
 Format:
 --------------------------------------------------------
 | magic(4Bytes) | type(4Bytes) | len(4Bytes) | payload |
 --------------------------------------------------------
 
 --------------------------------------------------------
 | 0xFEADDEAF | 0x01	 | len(4Bytes) | ip | port
 --------------------------------------------------------
 */
struct tshProtocol {
	uint32_t magic;
	uint32_t type;
	uint32_t length;

	// 需要连接对象的IP和端口
	uint32_t conn_ip;
	uint16_t conn_port;
	
	// 监听的TCP的IP和端口
	uint32_t listen_ip;
	uint16_t listen_port;
};
#define TSH_PROT_HEADER_LEN (int)sizeof(struct tshProtocol)
#define MAX_PAYLOAD_LEN 10240

#ifndef __cplusplus
#define true 1
#define false 0
#define bool int
#endif

static inline ssize_t udpRecvfrom(int s, void *data, size_t dataLen, struct sockaddr_in *srcAddr) {
	int clientAddrLen = sizeof(struct sockaddr_in);
	struct sockaddr_in clientAddr;
	ssize_t ret;
	
	ret = recvfrom(s, data, dataLen,
				   0, (struct sockaddr *)&clientAddr,
				   (socklen_t *)&clientAddrLen);
	if (srcAddr) {
		*srcAddr = clientAddr;
	}
	return ret;
}
static inline bool udpRecvPacket(int s, struct tshProtocol *data, struct sockaddr_in *srcAddr) {
	ssize_t ret = udpRecvfrom(s, data, TSH_PROT_HEADER_LEN, srcAddr);
	if (ret != (ssize_t)TSH_PROT_HEADER_LEN) {
		return false;
	}

	return true;
}

static inline bool udpRecvPacketData(int s, struct tshProtocol *data, struct sockaddr_in *srcAddr, char *outBuf, size_t outBufLen) {
	struct sockaddr_in clientAddr;
	int clientAddrLen = sizeof(struct sockaddr_in);
	ssize_t ret;
	char rawdata[MAX_PAYLOAD_LEN];
	
	if (NULL == data)
		return false;
	memset(outBuf, '\0', outBufLen);

	ret = recvfrom(s, rawdata, MAX_PAYLOAD_LEN,
				   0, (struct sockaddr *)&clientAddr,
				   (socklen_t *)&clientAddrLen);
	if (ret < TSH_PROT_HEADER_LEN || ret > MAX_PAYLOAD_LEN) {
		return false;
	} else if (ret > TSH_PROT_HEADER_LEN) {
		ssize_t plen = ret - TSH_PROT_HEADER_LEN;
		if (plen >= (ssize_t)outBufLen)
			return false;
		memcpy((void *)outBuf, rawdata + TSH_PROT_HEADER_LEN, (size_t)plen);
	}
	memcpy(data, rawdata, TSH_PROT_HEADER_LEN);
	
	if (srcAddr) {
		*srcAddr = clientAddr;
	}
	return true;
}

#ifdef __cplusplus
#include <string>
static inline bool udpRecvPacketData(int s, struct tshProtocol *data, struct sockaddr_in *srcAddr, std::string &payload) {
	char str[MAX_PAYLOAD_LEN];
	if (!udpRecvPacketData(s, data, srcAddr, str, MAX_PAYLOAD_LEN)) {
		return false;
	}
	payload = str;
	return true;
}
static inline bool __udpRecvPacketData(int s, struct tshProtocol *data, struct sockaddr_in *srcAddr, std::string &payload) {
	struct sockaddr_in clientAddr;
	int clientAddrLen = sizeof(struct sockaddr_in);
	ssize_t ret;
	char rawdata[10240];
	
	if (NULL == data)
		return false;
	
	ret = recvfrom(s, rawdata, 10240,
				   0, (struct sockaddr *)&clientAddr,
				   (socklen_t *)&clientAddrLen);
	if (ret < TSH_PROT_HEADER_LEN) {
		return false;
	} else if (ret > TSH_PROT_HEADER_LEN) {
		ssize_t plen = ret - TSH_PROT_HEADER_LEN;
		payload.clear();
		payload.resize(plen);
		memcpy((void *)payload.data(), rawdata + TSH_PROT_HEADER_LEN, (size_t)plen);
	}
	memcpy(data, rawdata, sizeof(struct tshProtocol));
	
	if (srcAddr) {
		*srcAddr = clientAddr;
	}
	return true;
}
#endif

static inline bool udpSendCString(int s, const char *pdata, size_t len, struct sockaddr_in *toAddr) {
	ssize_t ret = sendto(s, (const void *)pdata, len, 0, (const struct sockaddr *)toAddr, (socklen_t)sizeof(struct sockaddr_in));
	if (ret != len)
		return false;
	return true;
}

static inline bool udpSendPacket(int s, struct tshProtocol *data, struct sockaddr_in *toAddr) {
	return udpSendCString(s, (const char *)data, TSH_PROT_HEADER_LEN, toAddr);
}

#ifdef __cplusplus
static inline bool udpSendString(int s, std::string &str, struct sockaddr_in *toAddr) {
	return udpSendCString(s, str.c_str(), (size_t)str.length(), toAddr);
}
#endif

static inline bool udpSendPacketData(int s, struct sockaddr_in *toAddr, struct tshProtocol *header, const char *pdata) {
	size_t tlen = TSH_PROT_HEADER_LEN;
	if (pdata) {
		tlen += strlen(pdata);
	}
	void *newdata = malloc(tlen);
	memcpy(newdata, header, TSH_PROT_HEADER_LEN);
	if (pdata) {
		memcpy(newdata + TSH_PROT_HEADER_LEN, pdata, strlen(pdata));
	}

	ssize_t ret = sendto(s, (const void *)newdata, tlen, 0, (const struct sockaddr *)toAddr, (socklen_t)sizeof(struct sockaddr_in));
	free(newdata);
	if (ret != (ssize_t)tlen)
		return false;
	return true;
}

static inline struct sockaddr_in parseHostAndPort(const char *host, uint16_t port) {
	struct sockaddr_in udpAddr;
	
	struct hostent *hostent = gethostbyname(host);
	if (NULL == hostent) {
		udpAddr.sin_family = AF_UNSPEC;
		udpAddr.sin_addr.s_addr = 0;
		udpAddr.sin_port = 0;
		return udpAddr;
	}
	memcpy((void *)&udpAddr.sin_addr,
		   (void *)hostent->h_addr,
		   hostent->h_length);
	udpAddr.sin_family = AF_INET;
	udpAddr.sin_port = htons(port);
	
	return udpAddr;
}

static inline in_addr_t parseHostInetAddr(const char *host) {
	struct in_addr sin_addr;
	struct hostent *hostent = gethostbyname(host);
	if (NULL == hostent) {
		return 0;
	}

	memcpy((void *)&sin_addr,
		   (void *)hostent->h_addr,
		   hostent->h_length);

	return sin_addr.s_addr;
}


#ifdef __cplusplus

struct TshClient {

public:
	TshClient() {
		counter = 1;
		lastUpdate = time(NULL);
		clientAddr.sin_addr.s_addr = 0;
		clientAddr.sin_port = 0;
		memset((void *)&sendData, '\0', sizeof(sendData));
	}
	
	struct sockaddr_in clientAddr;
	uint32_t counter;
#define MAX_ALIVE_SECONDS (10 * 60)
	time_t lastUpdate;
	struct tshProtocol sendData;
	
	bool isEqual(const struct sockaddr_in &addr) {
		return addr.sin_addr.s_addr == clientAddr.sin_addr.s_addr
				&& addr.sin_port == clientAddr.sin_port;
	}
	bool isEqual(uint32_t ip, uint16_t port) {
		return ip == clientAddr.sin_addr.s_addr
		&& port == clientAddr.sin_port;
	}
	bool isValid() {
		return clientAddr.sin_addr.s_addr == 0 || clientAddr.sin_port == 0;
	}
};

#endif

////////////////这里是UDP Server监听所有的tsh的连接/////////////////
////////////////程序可以列出所有的当前所有的连接
//// tshd ----(udp)----> tshUdpServer
//// tsh  ----(tcp) list----> 发送命令可以列出所有的客户端
////			ip					counter		lastUpdate
////			192.168.24.21:3456	100			2018-10-21 12:32:12
////			192.168.24.32:1234	23			2018-10-21 12:32:12
////			192.168.24.54:3344	12			2018-10-21 12:32:12
////			192.168.24.67:16745	89			2018-10-21 12:32:12
//// tsh  ----(tcp) connect 192.168.24.21:3456----> 反向连接所有指定的tshd

//// tsh connect 192.168.24.21:3456这个时候就会创建一个tcp port然后bind
//// 然后发送给tshd(让tshd来连接这个tcp socket)
//// tsh -h localhost -p 12345 -c 192.168.24.21:3456 cb

//////////////
/*
 int udpSock = createUdpSocket();
 while(1) {
 struct sockaddr_in sServer;
 	if(!hasWaitConnectSignal(udpSock, sServer)) {
		 sleep(10);
		 continue;
 	}
 
 	// 有任务链接了
 	connect(sServer);
 }
 
 bool hasWaitConnectSignal(int udpSock, &struct sockaddr_in sServer) {
 	udpProtocol heartBeatdata;
 	struct sockaddr_in outSockAddr;
 
	 sendto(udpSock, &heartBeatdata);
 
 	if(recvfrom(udpSock, &outSockAddr)) {
		 sServer = outSockAddr;
		 return true;
 	}
	 return false;
 }
 
 */
//////////////

#endif
