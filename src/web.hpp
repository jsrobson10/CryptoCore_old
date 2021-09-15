
#pragma once

#include "transaction.hpp"

#include <list>
#include <unordered_map>
#include <functional>
#include <string>
#include <list>

namespace web
{
	Transaction* get_transaction(std::string txid);
	Transaction* get_transaction(const char* txid);
	void add_transaction(Transaction& t);
	void update_transaction(Transaction& t);
	void get_edge_nodes(Transaction*& node1, Transaction*& node2);
	void generate_new();
	void show_all();
	void cleanup();
	void update();
	void init();

	extern std::unordered_map<std::string, Transaction*> edge_nodes;
};
