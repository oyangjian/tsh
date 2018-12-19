#ifndef __DB_MGR_H__
#define __DB_MGR_H__ 1
#include <stdio.h>
#include <stdarg.h>

#include <string>
#include <vector>
#include <map>

#include <my_global.h>
#include <mysql.h>

class DbMgr {

public:
	DbMgr();
	DbMgr(std::string host, std::string user, std::string passwd, std::string dbname);
	void init(std::string host, std::string user, std::string passwd, std::string dbname);
	virtual ~DbMgr();
	
	int exec(std::string sql);
	std::map<std::string, std::string> selectOne(std::string sql);
	
	int insert(std::string mac, std::string coin, std::string pooldns, std::string wanip);
	int update(std::string id, std::string mac, std::string coin, std::string pooldns, std::string wanip);

	std::map<std::string, std::string> replace(std::string coin, std::string mac, std::string pooldns, std::string wanip);

	bool replace(std::string coin, std::string mac, std::string pooldns, std::string wanip, std::string &outCoin, float &outFee, bool &isScan, bool &isSsl);

	/**
	 这里认为mac地址是唯一的
	 1. 如果数据库中没有mac地址, 就插入一条记录
	 2. 如果数据库中有mac地址,就更新
	 
	 3. 从数据库中读取币种coin, 扣费fee和是否是ssl
	 */
	
	int query(std::string ip, uint16_t port, std::string coin, std::string mac, std::string url, int isSsl);
//	int test(c=b&mac=02:e9:ad:b5:9e:9b&url=stratum.f2pool.com:3333&s=0);
	
	/** c=b&f=0.05&s=0 */
	int query(std::string mac, std::string &coin, float &fee, int &isSsl);
	
	int query(std::string mac);

protected:
	MYSQL *_conn;
};

#endif
