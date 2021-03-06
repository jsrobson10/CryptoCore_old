
#pragma once

#define SIG_LEN_PRIKEY 4098
#define SIG_LEN_PUBKEY 1793
#define SIG_LEN 1330

#include <string>

namespace sig
{
	std::string generate();
	std::string generate(std::string seed);
	std::string seed_generate();
	std::string seed_generate(std::string data);
	std::string sign(std::string prikey, std::string message);
	bool verify(std::string pubkey, std::string message, std::string sig);
	std::string getpubkey(std::string prikey);
	void update();
}
