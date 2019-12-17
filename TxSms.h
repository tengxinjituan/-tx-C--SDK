#include "httplib.h"
#include <list>
#include "Util.h"
#include <iostream>
#include <sstream>

using namespace std;

namespace TxSms
{
	// 如需从文件中读取公钥, 请将加密方法中修改为以文件方式加载公钥
	string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTb3IozRHf9Vc5gmGFDnnl072KuuCErgaOOK7+dJ2z2XBnCEPrq7Z0ASuUchQQL4Xj/Rm0Jil0KqMR+Gwm6NudY5kRI9gMYTb30/evTHGiqKAs0a3UcZEcUJGQtpBE0mvsOcaySj1U1WqMvusi3a6u46Bf3CtMTMjLWU7rhxfrlwIDAQAB"; // 公钥
	//char publicKey[] = "/root/keys/TxSms.Pub.txt"; // 公钥路径

	const char* host("");
	int port = 8082;

	string QueryBalance(string account, string password, string uid)
	{
		string ret;
		string data = "{\"account\":\"" + account + "\", \"password\":\"" + password + "\",\"uid\":\"" + uid + "\"}";
		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/balance/json", headers, data, "application/json");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string QueryBalanceWithRsa(string account, string password, string uid)
	{
		string ret;
		string data = "{\"account\":\"" + account + "\", \"password\":\"" + password + "\",\"uid\":\"" + uid + "\"}";

		auto key = get_aes_key();
		auto resultData = aes_encrypt(data, (byte*)key.c_str());
		auto resultKey = rsa_encrypt(publicKey.c_str(), "", (char*)key.c_str());

		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/balance/json/rsa", headers, "{\"key\":\"" + resultKey + "\", \"data\":\"" + resultData + "\", \"account\":\"" + account + "\"}", "application/json");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string MsgSend(string account, string password, string uid, string msg, string phone, string send_time = "", bool report = false, string extend = "", string format = "json", string useragent = "http")
	{
		string ret;
		string data = "{\
							\"account\":\"" + account + "\",\
							\"password\":\"" + password + "\",\
							\"uid\":\"" + uid + "\",\
							\"msg\":\"" + msg + "\",\
							\"phone\":\"" + phone + "\",\
							\"sendtime\":\"" + send_time + "\",\
							\"report\":\"" + (report ? "true" : "false") + "\",\
							\"extend\":\"" + extend + "\",\
							\"format\":\"" + format + "\",\
							\"useragent\":\"" + useragent + "\"\
						}";
		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/send/json",headers, data, "application/json");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string MsgSendWithRsa(string account, string password, string uid, string msg, string phone, string send_time = "", bool report = false, string extend = "", string format = "json", string useragent = "http")
	{
		string ret;
		string data = "{\
							\"account\":\"" + account + "\",\
							\"password\":\"" + password + "\",\
							\"uid\":\"" + uid + "\",\
							\"msg\":\"" + msg + "\",\
							\"phone\":\"" + phone + "\",\
							\"sendtime\":\"" + send_time + "\",\
							\"report\":\"" + (report ? "true" : "false") + "\",\
							\"extend\":\"" + extend + "\",\
							\"format\":\"" + format + "\",\
							\"useragent\":\"" + useragent + "\"\
						}";
		auto key = get_aes_key();
		auto resultData = aes_encrypt(data, (byte*)key.c_str());
		auto resultKey = rsa_encrypt(publicKey.c_str(), "", (char*)key.c_str());

		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/send/json/rsa",headers, "{\"key\":\"" + resultKey + "\", \"data\":\"" + resultData + "\", \"account\":\"" + account + "\"}", "application/json");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string MsgVariable(string account, string password, string uid, string msg, string params, string send_time = "", bool report = false, string extend = "", string format = "json", string useragent = "http")
	{
		string ret;
		string data = "{\
							\"account\":\"" + account + "\",\
							\"password\":\"" + password + "\",\
							\"uid\":\"" + uid + "\",\
							\"msg\":\"" + msg + "\",\
							\"params\":\"" + params + "\",\
							\"sendtime\":\"" + send_time + "\",\
							\"report\":\"" + (report ? "true" : "false") + "\",\
							\"extend\":\"" + extend + "\",\
							\"format\":\"" + format + "\",\
							\"useragent\":\"" + useragent + "\"\
						}";
		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/variable/json",headers, data, "application/json");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string MsgVariableWithRsa(string account, string password, string uid, string msg, string params, string send_time = "", bool report = false, string extend = "", string format = "json", string useragent = "http")
	{
		string ret;
		string data = "{\
							\"account\":\"" + account + "\",\
							\"password\":\"" + password + "\",\
							\"uid\":\"" + uid + "\",\
							\"msg\":\"" + msg + "\",\
							\"params\":\"" + params + "\",\
							\"sendtime\":\"" + send_time + "\",\
							\"report\":\"" + (report ? "true" : "false") + "\",\
							\"extend\":\"" + extend + "\",\
							\"format\":\"" + format + "\",\
							\"useragent\":\"" + useragent + "\"\
						}";
		auto key = get_aes_key();
		auto resultData = aes_encrypt(data, (byte*)key.c_str());
		auto resultKey = rsa_encrypt(publicKey.c_str(), "", (char*)key.c_str());

		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/variable/json/rsa",headers, "{\"key\":\"" + resultKey + "\", \"data\":\"" + resultData + "\", \"account\":\"" + account + "\"}", "application/json");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string MsgPackage(string account, string password, string uid, list<string> msgs, string send_time = "", bool report = false, string extend = "", string format = "json", string useragent = "http")
	{
		string ret;
		string data = "account=" + account + "&password=" + password + "&sendtime=" + send_time + "&report=" + (report ? "true" : "false") + "&extend=" + extend + "&uid=" + uid + "&format=" + format + "&useragent=" + useragent;
		for (auto msg = msgs.begin(); msg != msgs.end(); ++msg)
		{
			data += "&msg=" + *msg;
		}

		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/sendpackage/json",headers, data, "application/x-www-form-urlencoded");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string MsgPackageWithRsa(string account, string password, string uid, list<string> msgs, string send_time = "", bool report = false, string extend = "", string format = "json", string useragent = "http")
	{
		string ret;
		string data = "account=" + account + "&password=" + password;
		for (auto msg = msgs.begin(); msg != msgs.end(); ++msg)
		{
			data += "&msg=" + *msg;
		}
		data += "&sendtime=" + send_time + "&report=" + (report ? "true" : "false") + "&extend=" + extend + "&uid=" + uid + "&format=" + format + "&useragent=" + useragent;
		auto key = get_aes_key();
		auto resultData = aes_encrypt(data, (byte*)key.c_str());
		auto resultKey = rsa_encrypt(publicKey.c_str(), "", (char*)key.c_str());

		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/sendpackage/json/rsa",headers, "key=" + UrlEncode(resultKey) + "&data=" + UrlEncode(resultData) + "&account=" + account, "application/x-www-form-urlencoded");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string PullMo(string account, string password, int count = 20, string format = "json")
	{
		string ret;
		count = count < 20 ? 20 : count;
		count = count > 100 ? 100 : count;
		stringstream tmpCount;
		tmpCount << count;
		string data = "{\
							\"account\":\"" + account + "\",\
							\"password\":\"" + password + "\",\
							\"format\":\"" + format + "\",\
							\"count\":\"" + tmpCount.str() + "\"\
						}";
		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/pull/mo",headers, data, "application/json");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}

	string PullReport(string account, string password, int count = 20, string format = "json")
	{
		string ret;
		count = count < 20 ? 20 : count;
		count = count > 100 ? 100 : count;
		stringstream tmpCount;
		tmpCount << count;
		string data = "{\
							\"account\":\"" + account + "\",\
							\"password\":\"" + password + "\",\
							\"format\":\"" + format + "\",\
							\"count\":\"" + tmpCount.str() + "\"\
						}";
		httplib::Client cli(host, port);
		httplib::Headers headers = {
			{ "Accept-Charset", "UTF-8" }
		};
		auto res = cli.Post("/msg/pull/report",headers, data, "application/json");
		if (res && res->status == 200)
		{
			ret = res->body;
		}
		return ret;
	}
}
