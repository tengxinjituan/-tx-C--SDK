#include "httplib.h"
#include <base64.h>
#include "rsa.h"
#include <aes.h>
#include "hex.h"
#include <filters.h>
#include "randpool.h"
#include "files.h"
#include <modes.h>
#include "md5.h"
#include <osrng.h>
#include <list>
#include <iostream>
#include <sstream>

using namespace std;

#pragma region url
unsigned char ToHex(unsigned char x)
{
	return  x > 9 ? x + 55 : x + 48;
}

unsigned char FromHex(unsigned char x)
{
	unsigned char y;
	if (x >= 'A' && x <= 'Z') y = x - 'A' + 10;
	else if (x >= 'a' && x <= 'z') y = x - 'a' + 10;
	else if (x >= '0' && x <= '9') y = x - '0';
	else assert(0);
	return y;
}

std::string UrlEncode(const std::string& str)
{
	std::string strTemp = "";
	size_t length = str.length();
	for (size_t i = 0; i < length; i++)
	{
		if (isalnum((unsigned char)str[i]) ||
			(str[i] == '-') ||
			(str[i] == '_') ||
			(str[i] == '.') ||
			(str[i] == '~'))
			strTemp += str[i];
		else if (str[i] == ' ')
			strTemp += "+";
		else
		{
			strTemp += '%';
			strTemp += ToHex((unsigned char)str[i] >> 4);
			strTemp += ToHex((unsigned char)str[i] % 16);
		}
	}
	return strTemp;
}

std::string UrlDecode(const std::string& str)
{
	std::string strTemp = "";
	size_t length = str.length();
	for (size_t i = 0; i < length; i++)
	{
		if (str[i] == '+') strTemp += ' ';
		else if (str[i] == '%')
		{
			assert(i + 2 < length);
			unsigned char high = FromHex((unsigned char)str[++i]);
			unsigned char low = FromHex((unsigned char)str[++i]);
			strTemp += high * 16 + low;
		}
		else strTemp += str[i];
	}
	return strTemp;
}
#pragma endregion

#pragma region Base64

string base64_encode(string plainText)
{
	string cipher;
	CryptoPP::StringSource(plainText, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(cipher)));
	return cipher;
}

string base64_decode(string plainText)
{
	string cipher_str;
	CryptoPP::StringSource(plainText, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(cipher_str)));
	return cipher_str;
}
#pragma endregion

#pragma region Aes

string get_aes_key() {
	const int SIZE_CHAR = 16; // 长度
	const char CCH[] = "_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	string ch = "";
	srand(::time(0));
	for (int i = 0; i < SIZE_CHAR; i++)
	{
		int x = rand() % (sizeof(CCH) - 1);
		ch += CCH[x];
	}
	return ch;
}

string aes_encrypt(string &plainText, byte* key)
{
	string cipherText;
	CryptoPP::ECB_Mode< CryptoPP::AES >::Encryption  Encryptor(key, strlen((char*)key));
	CryptoPP::StringSource(plainText, true, new CryptoPP::StreamTransformationFilter(Encryptor, new CryptoPP::StringSink(cipherText), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));
	string cipherTextHex = base64_encode(cipherText);
	return cipherTextHex;
}

string aes_decrypt(string &cipherText, byte* key)
{
	string tempCipherText;
	string decryptedText;
	tempCipherText = base64_decode(cipherText);
	CryptoPP::ECB_Mode< CryptoPP::AES >::Decryption Decryptor(key, sizeof(key));
	CryptoPP::StringSource(tempCipherText, true, new CryptoPP::StreamTransformationFilter(Decryptor, new CryptoPP::StringSink(decryptedText), CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));
	return decryptedText;
}

#pragma endregion

#pragma region Rsa

void generate_rsa_key(unsigned int keyLength, const char* privFilename, const char* pubFilename, const char* seed)
{
	CryptoPP::RandomPool randPool;
	randPool.IncorporateEntropy((byte*)seed, strlen(seed));

	CryptoPP::RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	CryptoPP::Base64Encoder privFile(new CryptoPP::FileSink(privFilename));
	priv.AccessMaterial().Save(privFile);
	privFile.MessageEnd();

	CryptoPP::RSAES_OAEP_SHA_Encryptor pub(priv);
	CryptoPP::Base64Encoder pubFile(new CryptoPP::FileSink(pubFilename));
	pub.AccessMaterial().Save(pubFile);
	pubFile.MessageEnd();
}

string rsa_encrypt(const char* pubFilename, const char* seed, const char* message)
{
	//CryptoPP::FileSource pubFile(pubFilename, true, new CryptoPP::Base64Decoder); // 如需以文件方式使用公钥, 请放开该行, 否则请注释
	CryptoPP::StringSource pubFile(pubFilename, true, new CryptoPP::Base64Decoder); // 如需以字符串方式使用公钥, 请放开该行, 否则请注释
	CryptoPP::RSAES_PKCS1v15_Encryptor pub(pubFile);

	CryptoPP::RandomPool randPool;
	randPool.IncorporateEntropy((byte*)seed, strlen(seed));

	std::string result;
	CryptoPP::StringSource(message, true, new CryptoPP::PK_EncryptorFilter(randPool, pub, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result))));
	return result;
}

string rsa_decrypt(const char* privFilename, const char* seed, const char* ciphertext)
{
	//CryptoPP::FileSource privFile(privFilename, true, new CryptoPP::Base64Decoder);
	CryptoPP::StringSource privFile(privFilename, true, new CryptoPP::Base64Decoder);
	CryptoPP::RSAES_PKCS1v15_Decryptor priv(privFile);
	std::string result;
	CryptoPP::RandomPool randPool;
	randPool.IncorporateEntropy((byte*)seed, strlen(seed));

	CryptoPP::StringSource(ciphertext, true, new CryptoPP::Base64Decoder(new CryptoPP::PK_DecryptorFilter(randPool, priv, new CryptoPP::StringSink(result))));
	return result;
}

#pragma endregion
