
#pragma once

#include <list>
#include <string>

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

class Transaction;

class Transaction
{

public:

	Transaction();
	Transaction(const char** bytes, size_t* len);
	Transaction(Transaction& t);

	const char* get_errors();

	bool is_valid();
	bool is_finalized();
	bool is_confirmed();

	void finalize();

	std::string to_string(int indent);
	char* serialize(char* data);
	size_t serialize_len();

	std::string get_txid();
	std::string get_hash();

	static uint64_t calculate_fee(unsigned int in, unsigned int out, unsigned int extra);

	uint64_t get_total();
	uint64_t get_fee();

	uint64_t get_created();
	uint64_t get_received();

	void add_input(std::string key_pri, uint64_t amount);
	void add_output(std::string address, uint64_t amount);
	void add_output(std::string address, uint64_t amount, std::string message);

	std::string get_pubkey();

private:

	size_t count_extra_data();

	char* serialize_t(char* data);
	size_t serialize_t_len();

	struct InputNew
	{
		std::string key_pri;
		uint64_t amount;
	};
	
	struct Input
	{
		std::string sig;
		std::string key_pub;
		uint64_t amount;
	};

	struct Output
	{
		std::string msg;
		std::string address;
		uint64_t amount;
	};
		
	uint64_t created;
	uint64_t received;

	bool confirmed;
	bool finalized;
	bool valid;

	std::string txid;
	std::list<InputNew> inputs_new;
	std::list<Input> inputs;
	std::list<Output> outputs;
};

