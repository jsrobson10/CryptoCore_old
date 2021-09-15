
#pragma once

#include <list>
#include <string>
#include <atomic>

#include <json/json.h>

/*
 *
 * A transaction can either be confirmed (in the blockchain) or unconfirmed (in the pool).
 *
 * For a transaction to be valid:
 *   - the combined inputs must be equal to the combined outputs and the fee
 *   - the fee will be 1
 *   - all signatures in inputs must be valid
 *
 */

extern std::atomic<uint64_t> transaction_hashrate;

class Transaction
{

public:

	Transaction();
	Transaction(const char* bytes, size_t len, bool trusted);
	Transaction(Transaction& t);

	const char* get_errors();
	
	bool is_confirmed();
	bool is_valid();

	bool has_prikey();
	int has_address(std::string address);

	void finalize();

	Json::Value to_json();

	char* serialize(char* data);
	size_t serialize_len();

	char* serialize_t(char* data);
	size_t serialize_t_len();

	std::string get_hash();
	uint64_t get_total();

	void add_input(std::string key_pri, uint64_t amount, uint64_t balance, std::string prev, const std::list<std::string>& sources);
	void add_output(std::string address, uint64_t amount);
	void add_output(std::string address, uint64_t amount, std::string message);

	int count_inputs();
	int count_outputs();

	void set_input_next(int pos, std::string next);

	void set_verified1(std::string id);
	void set_verified2(std::string id);

	bool add_confirm(std::string id);
	int count_confirms();

	struct InputNew
	{
		std::string prikey;
		std::string address;
		std::string prev;
		std::string next;
		std::list<std::string> sources;
		uint64_t balance;
		uint64_t amount;
	};
	
	struct Input
	{
		std::string sig;
		std::string pubkey;
		std::string address;
		std::string prev;
		std::string next;
		std::list<std::string> sources;
		uint64_t balance;
		uint64_t amount;
	};

	struct Output
	{
		std::string msg;
		std::string address;
		std::string referenced;
		uint64_t amount;
	};
		
	uint64_t work;
	uint64_t created;
	uint64_t received;
	uint64_t pos;

	bool finalized;
	bool valid;

	std::string verifies[2];
	std::string confirms[3];
	
	std::string txid;
	std::string txnoise;
	std::string token;
	std::list<InputNew> inputs_new;
	std::list<Input> inputs;
	std::list<Output> outputs;
};

