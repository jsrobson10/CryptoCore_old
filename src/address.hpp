
#pragma once

#include <string>

namespace address
{
	bool verify(std::string address);
	std::string get_hash(std::string address);
	std::string from_hash(std::string hash);
	std::string from_pubkey(std::string pubkey);
	std::string from_prikey(std::string prikey);
	std::string set_data(std::string address, std::string data);
	std::string get_data(std::string address);
}
