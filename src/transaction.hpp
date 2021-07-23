
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

class Transaction
{

public:

	Transaction();
	Transaction(const char* bytes, size_t len);
	
	bool is_valid();
	bool is_finalized();
	bool is_confirmed();

	void finalize();

	std::string to_string();
	char* serialize(char* data);
	size_t serialize_len();

	std::string get_txid();
	std::string get_hash();

	float get_total();
	float get_fee();

	unsigned long get_created();
	unsigned long get_received();

	void add_input(std::string key_pri, float amount);
	void add_output(std::string address, float amount);

private:

	char* serialize_t(char* data);
	size_t serialize_t_len();

	struct InputNew
	{
		std::string key_pri;
		float amount;
	};
	
	struct Input
	{
		std::string sig;
		std::string key_pub;
		float amount;
	};

	struct Output
	{
		std::string address;
		float amount;
	};
		
	unsigned long created;
	unsigned long received;

	bool confirmed;
	bool finalized;
	bool valid;

	float total;
	float fee;

	std::string txid;
	std::list<InputNew> inputs_new;
	std::list<Input> inputs;
	std::list<Output> outputs;
};

