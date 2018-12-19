#include <string>
#include <vector>
#include <map>

#include "DbMgr.h"
#include "StringUtils.h"

#if 0
#define verbose printf
#else
#define verbose(a...) do { } while(0)
#endif

#define log printf
#define err printf

DbMgr::DbMgr() {
}
DbMgr::DbMgr(std::string host, std::string user, std::string passwd, std::string dbname) {
	init(host, user, passwd, dbname);
}
void DbMgr::init(std::string host, std::string user, std::string passwd, std::string dbname) {
	_conn = mysql_init(NULL);
	if (_conn == NULL) {
		fprintf(stderr, "%s\n", mysql_error(_conn));
		exit(1);
	}
	
	if (mysql_real_connect(_conn, host.c_str(), user.c_str(), passwd.c_str(),
						   dbname.c_str(), 0, NULL, 0) == NULL) {
		err("real connect error %s\n", mysql_error(_conn));
		mysql_close(_conn);
	}

	printf("MySQL client version: %s\n", mysql_get_client_info());
}

DbMgr::~DbMgr() {
	mysql_close(_conn);
}

int DbMgr::exec(std::string sql) {
	if (mysql_query(_conn, sql.c_str())) {
		err("exec error %s\n", mysql_error(_conn));
		return -1;
	}
	return (int)mysql_affected_rows(_conn);
}

std::vector<std::string> getFieldVector(MYSQL_RES *result) {
	MYSQL_FIELD *field;
	std::vector<std::string> fieldArr;
	while(field = mysql_fetch_field(result)) {
		fieldArr.push_back(field->name);
	}
	return fieldArr;
}

std::map<std::string, std::string> DbMgr::selectOne(std::string sql) {
	std::map<std::string, std::string> recordMap;
	if (mysql_query(_conn, sql.c_str())) {
		err("select one error %s\n", mysql_error(_conn));
		return recordMap;
	}

	MYSQL_RES *result = mysql_store_result(_conn);
	uint32_t num_fields = mysql_num_fields(result);
	my_ulonglong rows = mysql_num_rows(result);
	verbose("num fields %d %d\n", rows, num_fields);

	std::vector<std::string> filedVector = getFieldVector(result);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result)))	{
		for(int i = 0; i < num_fields; i++) {
			std::string name = filedVector[i];
			std::string value = row[i] ? row[i] : "";
			recordMap[name] = value;
			verbose("%s = %s ", name.c_str(), value.c_str());
		}
		verbose("\n");
	}
	mysql_free_result(result);
	return recordMap;
}

int DbMgr::insert(std::string coin, std::string mac, std::string pooldns, std::string wanip) {
	// mac -->
	std::string poolip = "-";
	uint16_t poolport = 0;
	std::string sql =
		vfstr::format("insert into pool (coin,node,dns,ip,port,from_wan_ip,last_update) "
					" values "
					"('%s','%s','%s','%s','%d','%s',FROM_UNIXTIME(%d))",
					coin.c_str(), mac.c_str(), pooldns.c_str(),
					poolip.c_str(), poolport,
					wanip.c_str(), time(NULL)
					);
	verbose("sql %s\n", sql.c_str());
	
	return exec(sql);
}

int DbMgr::update(std::string id, std::string coin, std::string mac, std::string pooldns, std::string wanip) {
	// mac -->
	std::string poolip = "-";
	uint16_t poolport = 0;
	std::string sql =
	vfstr::format("update pool set coin='%s',node='%s',dns='%s',ip='%s',port='%d',from_wan_ip='%s',last_update=FROM_UNIXTIME(%d) where id='%s'",
					coin.c_str(), mac.c_str(), pooldns.c_str(),
					poolip.c_str(), poolport,
					wanip.c_str(), time(NULL), id.c_str()
					);
	verbose("sql %s\n", sql.c_str());

	return exec(sql);
}

std::map<std::string, std::string> DbMgr::replace(std::string coin, std::string mac, std::string pooldns, std::string wanip) {
	std::string sql = "select id,coin,fee,is_scan,is_ssl,confirm_coin,confirm_fee,confirm_is_scan,confirm_is_ssl from pool where node='" + mac + "'";
	verbose("sql %s\n", sql.c_str());
	std::map<std::string, std::string> recordMap = selectOne(sql);
	if (recordMap.empty()) {
		insert(coin, mac, pooldns, wanip);
	} else {
		std::string id = recordMap["id"];
		update(id, coin, mac, pooldns, wanip);
	}
	return recordMap;
}

bool DbMgr::replace(std::string coin, std::string mac, std::string pooldns, std::string wanip,
					std::string &outCoin, float &outFee, bool &isScan, bool &isSsl) {
	std::map<std::string, std::string> retMap = replace(coin, mac, pooldns, wanip);
	if (retMap.empty())
		return false;
	outCoin = retMap["confirm_coin"];
	outFee = vfstr::stof(retMap["confirm_fee"]);
	isScan = vfstr::stoi(retMap["confirm_is_scan"]);
	isSsl = vfstr::stoi(retMap["confirm_is_ssl"]);
	return true;
}

time_t String2time_t(const std::string& strDateTime){
	tm t;
	strptime(strDateTime.c_str(), "%F %T", &t);
	return mktime(&t);
}

#ifdef TEST

// 上行
// c=b&mac=02:e9:ad:b5:9e:9b&url=stratum.f2pool.com:3333&s=0
// 下行
// c=b&pw=xxx&scan=0&f=0.05&s=1
int main(int argc, char **argv) {
	DbMgr dbmgr("localhost", "root", "BitVF_2018", "pool");
	
	bool isSsl = true;
	std::string mac = "02:e9:ad:b5:9e:9b";
	std::string coin = "b";
	std::string url = "stratum.f2pool.com:3333";
	if (isSsl) {
		url = (std::string)"ssl://" + url;
	}
	std::string wanip = "123.123.252.174:55328";
	uint16_t port = 55328;
	//dbmgr.insert(coin, mac, url, wanip);
	
	dbmgr.replace(coin, mac, url, wanip);
	
	return 0;
}
#endif
