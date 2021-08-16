
#include "sig.hpp"
#include "address.hpp"
#include "base58.hpp"
#include "helpers.hpp"

#include <openssl/sha.h>

#include <cstring>

#define ADDRESS_HEADER 0x37

bool address::verify(std::string address)
{
	uint8_t checksum[32];

	address = base58::decode(address);

	if(address[0] == ADDRESS_HEADER && address.length() == 25)
	{
		SHA256((uint8_t*)address.c_str() + 1, 20, checksum);

		return ((uint8_t)address[21] == checksum[0]) && ((uint8_t)address[22] == checksum[1]) &&
			   ((uint8_t)address[23] == checksum[2]) && ((uint8_t)address[24] == checksum[3]);
	}

	return false;
}

std::string address::gethash(std::string address)
{
	return base58::decode(address).substr(1, 20);
}

std::string address::fromhash(std::string hash)
{
	if(hash.length() != 20)
	{
		return "";
	}
		
	uint8_t address[53];

	address[0] = ADDRESS_HEADER;

	memcpy(address + 1, hash.c_str(), 20);
	SHA256(address + 1, 20, address + 21);
	
	return base58::encode((char*)address, 25);
}

std::string address::frompubkey(std::string pubkey)
{
	unsigned char hash[32];

	SHA256((const unsigned char*)pubkey.c_str(), pubkey.length(), hash);

	return std::string((char*)hash, 20);
}

std::string address::fromprikey(std::string prikey)
{
	std::string pubkey = sig::getpubkey(prikey);

	return address::frompubkey(pubkey);
}

