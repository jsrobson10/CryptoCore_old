
#pragma once

#include "transaction.hpp"

#include <string>
#include <stack>
#include <list>

class Control
{
public:

	Control();

	void broadcast_new_transaction(Transaction* t);

	int process_new_transaction(Transaction* t);

	bool contains_id(std::string id);

private:

	std::list<std::string> received_ids;

	uint32_t chainstate[2];
};
