
#pragma once

#include <string>

namespace address
{
	bool verify(std::string address);
	std::string gethash(std::string address);
	std::string fromhash(std::string hash);
	std::string frompubkey(std::string pubkey);
	std::string fromprikey(std::string prikey);
}
