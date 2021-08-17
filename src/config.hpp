
#pragma once

#include <string>

namespace config
{
	void load();
	void generate();

	extern std::string http_auth;
	extern int workers;
};
