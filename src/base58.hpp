
#pragma once

#include <string>

namespace base58
{
	std::string encode(const char* data, size_t len);
	std::string decode(const char* data, size_t len);
	std::string encode(std::string data);
	std::string decode(std::string data);
};
