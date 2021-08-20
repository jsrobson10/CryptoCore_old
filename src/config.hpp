
#pragma once

#include <string>

namespace config
{
	void load();
	void generate();

	extern std::string http_auth;
	extern int cache_size;
	extern int workers;
};
