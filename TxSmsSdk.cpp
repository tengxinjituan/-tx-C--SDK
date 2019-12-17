/*
加密使用crypto++ 8.2
源码下载地址: https://www.cryptopp.com/cryptopp820.zip

http请求相关使用 httplib.h, 可根据需求更换其他类库

SDK函数调用时,参数使用UTF-8字符
*/
#include <iostream>
#include "TxSms.h"

using namespace std;


int main()
{
	TxSms::publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTb3IozRHf9Vc5gmGFDnnl072KuuCErgaOOK7+dJ2z2XBnCEPrq7Z0ASuUchQQL4Xj/Rm0Jil0KqMR+Gwm6NudY5kRI9gMYTb30/evTHGiqKAs0a3UcZEcUJGQtpBE0mvsOcaySj1U1WqMvusi3a6u46Bf3CtMTMjLWU7rhxfrlwIDAQAB";
	TxSms::host = "10.10.50.3"; // host仅为域名, 不包含"http://"和"/"等其他字符
	TxSms::port = 8082;
	auto account = "admin_lh";
	auto password = "123asd";
	auto uid = "1000103";

	string spd = "--------------------------------------------";

	{
		cout << "余额查询" << endl;
		auto body = TxSms::QueryBalance(account, password, uid);
		std::cout << "查询结果: " << body << endl << spd << endl;
	}
	{
		cout << "余额查询(加密)" << endl;
		auto body = TxSms::QueryBalanceWithRsa(account, password, uid);
		std::cout << "查询结果: " << body << endl << spd << endl;
	}
	{
		cout << "短信发送(加密)" << endl;
		auto body = TxSms::MsgSendWithRsa(account, password, uid, "【内测】您的验证码为：123456", "13000000000,13900000000");
		std::cout << "发送结果: " << body << endl << spd << endl;
	}
	{
		cout << "变量短信(加密)" << endl;
		auto body = TxSms::MsgVariableWithRsa(account, password, uid, "【内测】您的验证码为：{$var}", "13000000000,123456;13900000000,656565");
		std::cout << "发送结果: " << body << endl << spd << endl;
	}
	{
	/*	cout << "短信包发送" << endl;
		list<string> msgs;
		msgs.push_back("132769909863|test1");
		msgs.push_back("132769909864|test2");
		msgs.push_back("132769909865|test3");

		auto body = TxSms::MsgPackage(account, password, uid, msgs);
		std::cout << "发送结果: " << body << endl << spd << endl;*/
	}
	{
		cout << "短信包发送(加密)" << endl;
		list<string> msgs;
		msgs.push_back("13276990986|中文1");
		msgs.push_back("13276990986|中文2");
		msgs.push_back("13276990986|中文3");

		auto body = TxSms::MsgPackageWithRsa(account, password, uid, msgs, "201908190909");
		std::cout << "发送结果: " << body << endl << spd << endl;
	}
	{
		cout << "拉取上行" << endl;
		auto body = TxSms::PullMo(account, password);
		std::cout << "结果: " << body << endl << spd << endl;
	}
	{
		cout << "拉取报告" << endl;
		auto body = TxSms::PullReport(account, password);
		std::cout << "结果: " << body << endl << spd << endl;
	}
	
	getchar();
	return 0;
}