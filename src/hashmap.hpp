
#pragma once

#include <string>

#include "database.hpp"

class Hashmap : public Database
{
public:

	Hashmap(std::string location, bool clear);
	Hashmap(std::string location);
	uint64_t get(const char* digest);
	bool remove(const char* digest);
	uint64_t create(const char* digest, size_t len);

private:

	uint64_t new_table();
};

