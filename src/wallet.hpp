
#pragma once

#include <string>
#include <list>

#include "transaction.hpp"

namespace wallet
{
	void init();
	void init_new();
	void cleanup();
	void add_transaction(Transaction& tx);
	void get_address_details(std::string address, std::string token, std::list<Transaction*> unconfirmed, uint64_t unconfirmed_limit, uint64_t& balance_confirmed, uint64_t& balance_unconfirmed);
	uint64_t get_prev(std::string& txid, uint64_t pos);
	uint64_t get_latest(std::string address);
};
