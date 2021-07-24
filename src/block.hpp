
#pragma once

#include <list>
#include <string>

#include "transaction.hpp"

class Block
{
public:
	
	Block(std::string blockhash_last);
	Block(const char** data, size_t* size);
	~Block();

	size_t serialize_len();
	char* serialize(char* data);
	
	void sign(std::string prikey);

	const char* get_errors();

	bool is_signed();
	bool is_valid();

	std::string get_work();
	std::string get_blockid();
	std::string get_lastblockhash();
	std::string to_string(int indent);

	uint64_t get_received();
	uint64_t get_created();

	std::list<Transaction*>* get_transactions();
	void add_transaction(Transaction& t);

private:

	size_t serialize_t_len();
	char* serialize_t(char* data);

	std::list<Transaction*> transactions;
	std::string blockhash_last;
	std::string blockid;
	std::string sig;

	uint64_t received;
	uint64_t created;

	bool signed_status;
	bool valid;
};
