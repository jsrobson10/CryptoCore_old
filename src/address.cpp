
#include "address.hpp"
#include "base58.hpp"
#include "ec.hpp"

#include <openssl/sha.h>

#include <cstring>

#define ADDRESS_HEADER_BIG   0xe0
#define ADDRESS_HEADER_SMALL 0x37

bool address::verify(std::string address)
{
	unsigned char checksum[32];

	address = base58::decode(address);

	if(address[0] == ADDRESS_HEADER_SMALL && address.length() == 25)
	{
		SHA256((const unsigned char*)address.c_str() + 1, 20, checksum);
		
		return (address[21] == checksum[0] && address[22] == checksum[1] &&
				address[23] == checksum[2] && address[24] == checksum[3]);
	}

	if(address[0] == ADDRESS_HEADER_BIG && address.length() == 35)
	{
		SHA256((const unsigned char*)address.c_str() + 1, 30, checksum);
		
		return (address[31] == checksum[0] && address[32] == checksum[1] &&
				address[33] == checksum[2] && address[34] == checksum[3]);
	}

	return false;
}

std::string address::get_hash(std::string address)
{
	address = base58::decode(address);
	
	if(address.length() == 25)
	{
		return address.substr(1, 20);
	}

	if(address.length() == 35)
	{
		return address.substr(1, 30);
	}

	return "";
}

std::string address::from_hash(std::string hash)
{
	unsigned char hash_c[63];

	if(hash.length() == 20)
	{
		hash_c[0] = ADDRESS_HEADER_SMALL;

		memcpy(hash_c + 1, hash.c_str(), 20);
		SHA256(hash_c + 1, 20, hash_c + 21);
		
		return base58::encode((char*)hash_c, 25);
	}

	if(hash.length() == 30)
	{
		hash_c[0] = ADDRESS_HEADER_BIG;

		memcpy(hash_c + 1, hash.c_str(), 30);
		SHA256(hash_c + 1, 30, hash_c + 31);

		return base58::encode((char*)hash_c, 35);
	}

	return "";
}

std::string address::set_data(std::string address, std::string data)
{
	std::string hash = get_hash(address);

	if(data.length() != 10)
	{
		return from_hash(std::string(hash.c_str(), 20));
	}

	else
	{
		char hash_c[30];

		memcpy(hash_c, hash.c_str(), 20);
		memcpy(hash_c + 20, data.c_str(), 10);

		return from_hash(std::string(hash_c, 30));
	}
}

std::string address::get_data(std::string address)
{
	std::string hash = get_hash(address);

	return hash.substr(20, 30);
}

std::string address::from_pubkey(std::string pubkey)
{
	unsigned char hash[53];

	hash[0] = ADDRESS_HEADER_SMALL;

	SHA256((const unsigned char*)pubkey.c_str(), pubkey.length(), hash + 1);
	SHA256(hash + 1, 20, hash + 21);

	return base58::encode((char*)hash, 25);
}

std::string address::from_prikey(std::string prikey)
{
	return address::from_pubkey(ec::get_pubkey(prikey));
}

