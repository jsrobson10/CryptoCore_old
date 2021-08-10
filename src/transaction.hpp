
#pragma once

#include <list>
#include <string>

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

class Transaction
{

public:

	Transaction();
	Transaction(const char* bytes, size_t len, const char** bytes_n, size_t* len_n);
	Transaction(Transaction& t);

	const char* get_errors();

	bool is_valid();
	bool is_finalized();
	bool is_confirmed();
	bool is_verified();

	bool has_prikey();
	int has_address(std::string address);
	void set_verified();

	void finalize();

	std::string to_string(int indent);
	Json::Value to_json();

	char* serialize(char* data);
	size_t serialize_len();

	char* serialize_t(char* data);
	size_t serialize_t_len();

	std::string get_txid();
	std::string get_hash();
	std::string get_prikey();

	uint64_t get_total();
	uint64_t get_created();
	uint64_t get_received();
	uint64_t get_pos();

	void add_input(std::string key_pri, uint64_t balance, std::string prev, const std::list<std::string>& sources);
	void add_output(std::string address, uint64_t amount);
	void add_output(std::string address, uint64_t amount, std::string message);

	int count_inputs();
	int count_outputs();

	void set_input_next(int pos, std::string next);

	void set_verified1(std::string id);
	void set_verified2(std::string id);
	void set_pos(uint64_t pos);

	bool add_confirm(std::string id);

private:

	struct InputNew
	{
		std::string prikey;
		std::string address;
		std::string prev;
		std::string next;
		std::list<std::string> sources;
		uint64_t balance;
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
	};

	struct Output
	{
		std::string msg;
		std::string address;
		uint64_t amount;
	};
		
	uint64_t pos;
	uint64_t created;
	uint64_t received;

	bool verified;
	bool confirmed;
	bool finalized;
	bool valid;

	std::string verifies[2];
	std::string confirms[3];

	std::string txid;
	std::list<InputNew> inputs_new;
	std::list<Input> inputs;
	std::list<Output> outputs;
};

