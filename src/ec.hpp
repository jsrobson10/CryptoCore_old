
#pragma once

#include <string>

namespace ec
{
	void init();
	std::string generate();
	std::string sign(std::string pri_key, std::string digest);
	bool verify(std::string pub_key, std::string digest, std::string sig);
	std::string get_pubkey(std::string pri_key);
	std::string get_address(std::string pub_key);
}
