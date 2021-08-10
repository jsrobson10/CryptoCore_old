
#pragma once

#include <string>
#include <list>

class Transaction;

namespace web
{
	Transaction* get_transaction(std::string txid);
	Transaction* get_transaction(const char* txid);
	Transaction* get_transaction(__uint128_t pos);
	bool find_transactions(std::list<Transaction*>& transactions, std::string after, int limit);
	void add_transaction(Transaction* t);
	void get_edge_nodes(std::string node1, std::string node2);
	void generate_new();
	void show_all();
	void cleanup();
	void init();
};
