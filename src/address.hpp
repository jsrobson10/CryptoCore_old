
#pragma once

#include <string>

#define ADDR_LEN 40

#define ADDR_DEPOSIT      1
#define ADDR_SECRET       2
#define ADDR_TRANSACTION  3
#define ADDR_TOKEN        4

namespace address
{
	int verify(std::string address);
	std::string gethash(std::string address);
	std::string fromhash(std::string hash, int type);
	std::string frompubkey(std::string pubkey);
	std::string fromprikey(std::string prikey);
}
