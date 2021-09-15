
#include "sig.hpp"
#include "address.hpp"
#include "base58.hpp"
#include "helpers.hpp"

#include <openssl/sha.h>

#include <cstring>

#define ADDR_LEN_HEAD 1
#define ADDR_LEN_DATA 32
#define ADDR_LEN_CHCK 7

#define ADDRESS_HEADER 0x37

// do this to prevent potential conflicts with other crypto checksums
const uint8_t CHECKSUM_MASKS[][ADDR_LEN_CHCK] = {
	{0x84, 0xe9, 0x86, 0x04, 0x0f, 0x5c, 0xa3}, // payment address
	{0xc8, 0xf0, 0x99, 0x75, 0x89, 0x65, 0x65}, // private key
	{0x63, 0xd6, 0x2c, 0x29, 0xaf, 0x52, 0xf5}, // transaction
	{0x20, 0x57, 0xd3, 0xc4, 0x6d, 0x39, 0x39}, // token
};

int address::verify(std::string address)
{
	uint8_t checksum[32];

	address = base58::decode(address);

	if(address[0] == ADDRESS_HEADER && address.length() == ADDR_LEN)
	{
		SHA256((uint8_t*)address.c_str() + 1, 32, checksum);

		for(int i = 0; i < sizeof(CHECKSUM_MASKS) / sizeof(*CHECKSUM_MASKS); i++)
		{
			if(checksum[0] ^ CHECKSUM_MASKS[i][0] == address[33] &&
			   checksum[1] ^ CHECKSUM_MASKS[i][1] == address[34] &&
			   checksum[2] ^ CHECKSUM_MASKS[i][2] == address[35] &&
			   checksum[3] ^ CHECKSUM_MASKS[i][3] == address[36] &&
			   checksum[4] ^ CHECKSUM_MASKS[i][4] == address[37] &&
			   checksum[5] ^ CHECKSUM_MASKS[i][5] == address[38] &&
			   checksum[6] ^ CHECKSUM_MASKS[i][6] == address[39])
			{
				return i;
			}
		}
	}

	return 0;
}

std::string address::gethash(std::string address)
{
	return base58::decode(address).substr(1, 32);
}

std::string address::fromhash(std::string hash, int type)
{
	if(hash.length() != 32)
	{
		return "";
	}
	
	uint8_t address[ADDR_LEN_HEAD + ADDR_LEN_DATA + 32];

	address[0] = ADDRESS_HEADER;

	memcpy(address + 1, hash.c_str(), 20);
	SHA256(address + 1, 32, address + 33);

	// add the checksum mask so the address is recognisable
	address[33] ^= CHECKSUM_MASKS[type][0];
	address[34] ^= CHECKSUM_MASKS[type][1];
	address[35] ^= CHECKSUM_MASKS[type][2];
	address[36] ^= CHECKSUM_MASKS[type][3];
	address[37] ^= CHECKSUM_MASKS[type][4];
	address[38] ^= CHECKSUM_MASKS[type][5];
	address[39] ^= CHECKSUM_MASKS[type][6];
	
	return base58::encode((char*)address, 40);
}

std::string address::frompubkey(std::string pubkey)
{
	unsigned char hash[32];

	SHA256((const unsigned char*)pubkey.c_str(), pubkey.length(), hash);

	return std::string((char*)hash, 32);
}

std::string address::fromprikey(std::string prikey)
{
	std::string pubkey = sig::getpubkey(prikey);

	return address::frompubkey(pubkey);
}

