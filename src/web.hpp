
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
	Transaction* get_transaction(uint64_t pos);
	uint64_t get_transaction_pos(const char* txid);
	Transaction* get_latest_from_address(std::string address);
	void find_transactions(uint64_t& at, std::function<bool (Transaction& tx)> callback);
	void get_address_info(std::string address, uint64_t &balance, Transaction*& latest, std::list<Transaction*>& sources_new, uint64_t sources_new_limit);
	uint64_t find_outputs(std::list<Transaction*>& transactions, std::string find, std::string after, uint64_t limit);
	uint64_t find_outputs(std::string find, std::string after, std::function<bool (Transaction& tx, Transaction::Output& out)> callback);
	uint64_t get_next_tx_pos();
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
