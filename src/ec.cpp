
#include "ec.hpp"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include <cstring>

EC_GROUP* ecgroup;

/*
 *
 * Key format:
 *
 * 30770201010420 ...private 256 bit... a00a06082a8648ce3d030107a14403420004 ...public 512 bit...
 *
 * 3059301306072a8648ce3d020106082a8648ce3d03010703420004 ...public 512 bit...
 *
 */

const unsigned char KEY_PUB_HEADER[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 
		0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 
		0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 
		0x42, 0x00, 0x04};

void ec::init()
{
	ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
}

std::string ec::generate()
{
	EC_KEY* key = EC_KEY_new();
	EC_KEY_set_group(key, ecgroup);
	EC_KEY_generate_key(key);

	char* pri_key = nullptr;
	int pri_len = i2d_ECPrivateKey(key, (unsigned char**)&pri_key);

	std::string key_pri(pri_key, pri_len);

	free(pri_key);
	
	EC_KEY_free(key);

	return key_pri;
}

std::string ec::sign(std::string key_pri, std::string digest)
{
	EC_KEY* key = EC_KEY_new();
	EC_KEY_set_group(key, ecgroup);

	const char* key_pri_c = key_pri.c_str();

	d2i_ECPrivateKey(&key, (const unsigned char**)&key_pri_c, key_pri.length());

	char* sig = new char[ECDSA_size(key)];
	unsigned int sig_len;

	ECDSA_sign(0, (unsigned char*)digest.c_str(), digest.length(), (unsigned char*)sig, &sig_len, key);

	std::string sig_str(sig, sig_len);

	EC_KEY_free(key);

	delete[] sig;

	return sig_str;
}

bool ec::verify(std::string key_pub, std::string digest, std::string sig)
{
	EC_KEY* key = EC_KEY_new();
	EC_KEY_set_group(key, ecgroup);

	char* key_pub_c = new char[key_pub.length() + sizeof(KEY_PUB_HEADER)];
	char* key_pub_c_n = key_pub_c;

	memcpy(key_pub_c, KEY_PUB_HEADER, sizeof(KEY_PUB_HEADER));
	memcpy(key_pub_c + sizeof(KEY_PUB_HEADER), key_pub.c_str(), key_pub.length());

	d2i_EC_PUBKEY(&key, (const unsigned char**)&key_pub_c_n, key_pub.length() + sizeof(KEY_PUB_HEADER));
	
	int result = ECDSA_verify(0, (unsigned char*)digest.c_str(), digest.length(), (unsigned char*)sig.c_str(), sig.length(), key);

	EC_KEY_free(key);

	delete[] key_pub_c;

	return (result == 1);
}

std::string ec::get_pubkey(std::string pri_key)
{
	return std::string(pri_key.c_str() + pri_key.length() - 64, 64);
}

std::string ec::get_address(std::string pub_key)
{
	char address[32];

	SHA256((unsigned char*)pub_key.c_str(), pub_key.length(), (unsigned char*)address);

	return std::string(address, 20);
}

