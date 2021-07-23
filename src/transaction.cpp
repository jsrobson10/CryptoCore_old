
#include "transaction.hpp"
#include "helpers.hpp"
#include "ec.hpp"

#include <openssl/sha.h>
#include <openssl/rand.h>

#include <cstring>

/*
 * 
 * Transaction binary format:
 *
 * (created, 8) (txid, 32) (inputs, 1) (outputs, 1) ...[inputs] [(amount, 4), (pubkey, 64)] ...[outputs] [(amount, 4), (address, 32)] ...[inputs] [(siglen, 1), (sig, siglen)]
 *
 */

Transaction::Transaction()
{
	char txid_c[32];

	RAND_bytes((unsigned char*)txid_c, 32);
	txid = std::string(txid_c, 32);

	created = get_micros();
	received = created;
	confirmed = false;
	finalized = false;
	valid = false;
	total = 0;
	fee = 1;
}

Transaction::Transaction(const char* bytes, size_t len)
{
/*	received = get_micros();
	created = get_netl(bytes);
	txid = std::string(bytes + 8, 32);

	confirmed = false;
	finalized = true;

	int inputs_len = bytes[40];
	int outputs_len = bytes[41];

	bytes += 42;

	for(int i = 0; i < inputs_len; i++)
	{
		Transaction::Input input;

		input.amount = get_netf(bytes);
		input.key_pub = std::string(bytes + 4, 64);
		inputs.push_back(input);

		bytes += 68;
	}

	for(int i = 0; i < outputs_len; i++)
	{
		Transaction::Output output;

		output.amount = get_netf(bytes);
		output.address = std::string(bytes + 4, 32);
		outputs.push_back(output);

		bytes += 36;
	}

	for(auto input = inputs.begin(); input < inputs.end(); input++)
	{
		input->sig = std::string(bytes + 1, *(unsigned char*)bytes);
		bytes += 1 + *(unsigned char*)bytes;
	}*/
}

bool Transaction::is_valid()
{
	return this->valid;
}

bool Transaction::is_finalized()
{
	return this->finalized;
}

bool Transaction::is_confirmed()
{
	return this->confirmed;
}

size_t Transaction::serialize_t_len()
{
	size_t len_inputs = (finalized ? inputs.size() : inputs_new.size()) * 68;
	size_t len_outputs = outputs.size() * 36;

	return 42 + len_inputs + len_outputs;
}

char* Transaction::serialize_t(char* data)
{
	put_netl(data, created);
	memcpy(data + 8, txid.c_str(), txid.length());
	
	data[41] = outputs.size();

	// write finalized inputs
	
	if(finalized)
	{
		data[40] = (char)inputs.size();
		data += 42;
		
		for(Transaction::Input input : inputs)
		{
			put_netf(data, input.amount);
			memcpy(data + 4, input.key_pub.c_str(), 64);
			data += 68;
		}
	}

	// write unfinalized inputs

	else
	{
		data[40] = (char)inputs_new.size();
		data += 42;

		for(Transaction::InputNew input : inputs_new)
		{
			put_netf(data, input.amount);
			memcpy(data + 4, input.key_pri.c_str() + input.key_pri.length() - 64, 64);
			data += 68;
		}
	}

	// write outputs

	for(Transaction::Output output : outputs)
	{
		put_netf(data, output.amount);
		memcpy(data + 4, output.address.c_str(), 32);
		data += 36;
	}

	return data;
}

size_t Transaction::serialize_len()
{
	finalize();
	
	size_t len = serialize_t_len();

	for(Transaction::Input input : inputs)
	{
		len += 1 + input.sig.length();
	}

	return len;
}

char* Transaction::serialize(char* data)
{
	finalize();
	
	data = serialize_t(data);

	for(Transaction::Input input : inputs)
	{
		size_t sig_len = input.sig.length();

		data[0] = (char)sig_len;
		memcpy(data + 1, input.sig.c_str(), sig_len);
		data += 1 + sig_len;
	}

	return data;
}

void Transaction::finalize()
{
	// finalize can only be called once
	if(finalized)
	{
		return;
	}

	finalized = true;

	// get the hash of the transaction not including signatures
	
	char txhash_c[32];

	size_t txlen = serialize_t_len();
	char* tx = new char[txlen];

	serialize_t(tx);
	SHA256((unsigned char*)tx, txlen, (unsigned char*)txhash_c);

	std::string txhash(txhash_c, 32);

	delete[] tx;

	// convert all new inputs into inputs
	for(Transaction::InputNew input_new : inputs_new)
	{
		Transaction::Input input;

		input.amount = input_new.amount;
		input.key_pub = ec::get_pubkey(input_new.key_pri);
		input.sig = ec::sign(input_new.key_pri, txhash);

		inputs.push_back(input);
	}
}

std::string Transaction::get_txid()
{
	return txid;
}

std::string Transaction::get_hash()
{
	char txhash_c[32];

	size_t txlen = serialize_len();
	char* tx = new char[txlen];

	serialize(tx);
	SHA256((unsigned char*)tx, txlen, (unsigned char*)txhash_c);

	std::string txhash(txhash_c, 32);

	delete[] tx;

	return txhash;
}

float Transaction::get_total()
{
	return total;
}

float Transaction::get_fee()
{
	return fee;
}

unsigned long Transaction::get_created()
{
	return created;
}

unsigned long Transaction::get_received()
{
	return received;
}

void Transaction::add_input(std::string key_pri, float amount)
{
	Transaction::InputNew input;
	
	input.key_pri = key_pri;
	input.amount = amount;

	inputs_new.push_back(input);
}

void Transaction::add_output(std::string address, float amount)
{
	Transaction::Output output;

	output.address = address;
	output.amount = amount;

	outputs.push_back(output);
}

std::string Transaction::to_string()
{
	std::string out = "Transaction (\n  txid = " + to_hex(txid) +
			", \n  created = " + std::to_string(created) + 
			", \n  received = " + std::to_string(received) +
			", \n  fee = " + std::to_string(fee) +
			", \n  total = " + std::to_string(total) +
			", \n  confirmed = " + (is_confirmed() ? "1" : "0") +
			", \n  finalized = " + (is_finalized() ? "1" : "0") +
			", \n  valid = " + (is_valid() ? "1" : "0") +
			", \n  inputs = [";

	if(is_finalized())
	{
		for(Transaction::Input input : inputs)
		{
			out += "\n    (\n      pubkey = " + to_hex(input.key_pub) + ", \n      sig = " + to_hex(input.sig) + ", \n      amount = " + std::to_string(input.amount) + "\n    ), ";
		}
	}

	else
	{
		for(Transaction::InputNew input : inputs_new)
		{
			out += "\n    (\n      pubkey = " + to_hex(ec::get_pubkey(input.key_pri)) + ", \n      amount = " + std::to_string(input.amount) + "\n    ), ";
		}
	}

	out += "\n  ], \n  outputs = [";

	for(Transaction::Output output : outputs)
	{
		out += "\n    (\n      address = " + to_hex(output.address) + ", \n      amount = " + std::to_string(output.amount) + "\n    ), ";
	}

	return out + "\n  ]\n)\n";
}
