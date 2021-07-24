
#include "address.hpp"
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
 * (created, 8) (txid, 32) (inputs, 1) (outputs, 1) ...[inputs] [(amount, 4), (pubkey, 64)] ...[outputs] [(amount, 4), 20 or 30 (1 bit) msglen (7 bit), 1), (address, 20 (0) or 30 (1)), (msg, msglen)] ...[inputs] [(siglen, 1), (sig, siglen)]
 *
 */

#define TX_FEE 10000 // 1 coin

Transaction::Transaction()
{
	char txid_c[32];

	RAND_bytes((unsigned char*)txid_c, 32);
	txid = std::string(txid_c, 32);

	created = get_micros();
	received = created;
	confirmed = false;
	finalized = false;
	valid = true;
}

Transaction::Transaction(Transaction& t)
{
	created = t.created;
	received = t.received;
	confirmed = t.confirmed;
	finalized = t.finalized;
	valid = t.valid;
	txid = t.txid;

	inputs_new = std::list<Transaction::InputNew>(t.inputs_new);
	inputs = std::list<Transaction::Input>(t.inputs);
	outputs = std::list<Transaction::Output>(t.outputs);
}

Transaction::Transaction(const char** bytes, size_t* len)
{
	received = get_micros();
	created = get_netl(*bytes);
	txid = std::string(*bytes + 8, 32);

	confirmed = false;
	finalized = true;
	valid = true;

	if(*len < 42)
	{
		valid = false;
		return;
	}

	const char* end = *bytes + *len;
	
	int inputs_len = ((unsigned char*)*bytes)[40];
	int outputs_len = ((unsigned char*)*bytes)[41];

	if(inputs_len == 0 || outputs_len == 0 || *len < inputs_len * 69 + outputs_len * 24 + 42)
	{
		valid = false;
		return;
	}

	*bytes += 42;
	*len -= 42;

	// add the inputs
	for(int i = 0; i < inputs_len; i++)
	{
		Transaction::Input input;

		input.amount = get_netf(*bytes);
		input.key_pub = std::string(*bytes + 4, 64);
		inputs.push_back(input);

		*bytes += 68;
		*len -= 68;
	}

	// add the outputs
	for(int i = 0; i < outputs_len; i++)
	{
		Transaction::Output output;

		unsigned char msg_len = ((unsigned char*)*bytes)[4];
		bool address_flag = (msg_len & 128) != 0;
		int address_len = address_flag ? 30 : 20;

		msg_len &= 127;

		if(end < *bytes + 5 + address_len + msg_len)
		{
			valid = false;
			return;
		}

		output.amount = get_netf(*bytes);
		output.address = std::string(*bytes + 5, address_len);
		output.msg = std::string(*bytes + address_len + 5, msg_len);
		outputs.push_back(output);

		int c = 5 + address_len + msg_len;

		*bytes += c;
		*len -= c;
	}

	// add the inputs signatures
	for(auto input = inputs.begin(); input != inputs.end(); input++)
	{
		int o = ((unsigned char*)*bytes)[0];

		if(end < *bytes + o + 1 || o > SIG_LEN_MAX)
		{
			valid = false;
			return;
		}

		input->sig = std::string(*bytes + 1, o);
		*bytes += 1 + o;
		*len -= 1 + o;
	}
}

size_t Transaction::count_extra_data()
{
	size_t extra = 0;

	for(Transaction::Output output : outputs)
	{
		if(output.address.length() == 30)
		{
			extra += 10;
		}

		extra += output.msg.length();
	}

	return extra;
}

bool Transaction::is_valid()
{
	return get_errors() == nullptr;
}

const char* Transaction::get_errors()
{
	if(!this->valid)
	{
		return "invalid flag set";
	}

	if(!this->finalized)
	{
		return "finalized flag not set";
	}

	uint64_t total_in = 0;
	uint64_t total_out = 0;

	// calculate total in
	for(Transaction::Input input : inputs)
	{
		total_in += input.amount;
	}

	// calculate total out
	for(Transaction::Output output : outputs)
	{
		total_out += output.amount;
	}

	// cant transfer zero coins
	if(total_in == 0 || total_out == 0)
	{
		return "cannot transfer zero coins";
	}

	// invalid fee
	if(total_out > total_in || total_in - total_out < calculate_fee(inputs.size(), outputs.size(), count_extra_data()))
	{
		return "fee too low";
	}

	// check for invalid signatures
	
	size_t tx_len = serialize_t_len();
	char* tx = new char[tx_len];
	serialize_t(tx);

	char digest_c[32];
	SHA256((unsigned char*)tx, tx_len, (unsigned char*)digest_c);

	delete[] tx;

	std::string digest(digest_c, 32);

	for(Transaction::Input input : inputs)
	{
		if(!ec::verify(input.key_pub, digest, input.sig))
		{
			return "invalid signature";
		}
	}

	return nullptr;
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
	size_t len_outputs = 0;

	for(Transaction::Output output : outputs)
	{
		len_outputs += output.address.length() + output.msg.length() + 5;
	}

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
		int address_len = output.address.length() == 30 ? 30 : 20;
		unsigned char msg_len = (address_len == 30 ? 128 : 0) ^ (output.msg.length() & 127);

		data[4] = msg_len;
		
		put_netf(data, output.amount);
		memcpy(data + 5, output.address.c_str(), address_len);
		memcpy(data + 5 + address_len, output.msg.c_str(), msg_len & 127);
		data += 5 + address_len + (msg_len & 127);
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
	
	finalized = true;
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

uint64_t Transaction::get_total()
{
	uint64_t total = 0;

	if(finalized)
	{
		for(Transaction::Input input : inputs)
		{
			total += input.amount;
		}
	}
	
	else
	{
		for(Transaction::InputNew input : inputs_new)
		{
			total += input.amount;
		}
	}

	return total;
}

uint64_t Transaction::get_fee()
{
	uint64_t total_in = 0;
	uint64_t total_out = 0;
	
	if(finalized)
	{
		for(Transaction::Input input : inputs)
		{
			total_in += input.amount;
		}
	}
	
	else
	{
		for(Transaction::InputNew input : inputs_new)
		{
			total_in += input.amount;
		}
	}

	for(Transaction::Output output : outputs)
	{
		total_out += output.amount;
	}

	if(total_out > total_in)
	{
		return 0;
	}

	return total_in - total_out;
}

uint64_t Transaction::calculate_fee(unsigned int in, unsigned int out, unsigned int extra)
{
	// 1 transaction fee for every kilobyte, paying a min of 1 tx fee
	return ((42 + in * (69 + SIG_LEN_MAX) + out * 25 + extra) / 1024) * TX_FEE + TX_FEE;
}

uint64_t Transaction::get_created()
{
	return created;
}

uint64_t Transaction::get_received()
{
	return received;
}

void Transaction::add_input(std::string key_pri, uint64_t amount)
{
	if(finalized) return;

	Transaction::InputNew input;
	
	input.key_pri = key_pri;
	input.amount = amount;

	inputs_new.push_back(input);
}

void Transaction::add_output(std::string address, uint64_t amount)
{
	add_output(address, amount, "");
}

void Transaction::add_output(std::string address, uint64_t amount, std::string msg)
{
	if(finalized) return;

	Transaction::Output output;

	output.address = address::get_hash(address);
	output.amount = amount;
	output.msg = msg;

	outputs.push_back(output);
}

std::string Transaction::to_string(int indent)
{
	const char* error = get_errors();
	
	std::string out = calc_indent(indent)+"Transaction (" +
			"\n"+calc_indent(indent+1)+"txid = " + to_hex(txid) +
			"\n"+calc_indent(indent+1)+"created = " + std::to_string(created) + 
			"\n"+calc_indent(indent+1)+"received = " + std::to_string(received) +
			"\n"+calc_indent(indent+1)+"fee = " + display_coins(get_fee()) +
			"\n"+calc_indent(indent+1)+"total = " + display_coins(get_total()) +
			"\n"+calc_indent(indent+1)+"confirmed = " + (is_confirmed() ? "1" : "0") +
			"\n"+calc_indent(indent+1)+"finalized = " + (is_finalized() ? "1" : "0") +
			"\n"+calc_indent(indent+1)+"valid = " + (error ? ("0, \n"+calc_indent(indent+1)+"error = " + std::string(error)) : "1") +
			"\n"+calc_indent(indent+1)+"inputs = [";

	if(is_finalized())
	{
		for(Transaction::Input input : inputs)
		{
			out += "\n"+calc_indent(indent+2)+"(\n"+calc_indent(indent+3)+"pubkey = " + to_hex(input.key_pub) +
					"\n"+calc_indent(indent+3)+"sig = " + to_hex(input.sig) +
					"\n"+calc_indent(indent+3)+"amount = " + display_coins(input.amount) +
					"\n"+calc_indent(indent+2)+")";
		}
	}

	else
	{
		for(Transaction::InputNew input : inputs_new)
		{
			out += "\n"+calc_indent(indent+2)+"(\n"+calc_indent(indent+3)+"pubkey = " + to_hex(ec::get_pubkey(input.key_pri)) +
					"\n"+calc_indent(indent+3)+"amount = " + display_coins(input.amount) +
					"\n"+calc_indent(indent+2)+")";
		}
	}

	out += "\n"+calc_indent(indent+1)+"]\n"+calc_indent(indent+1)+"outputs = [";

	for(Transaction::Output output : outputs)
	{
		out += "\n"+calc_indent(indent+2)+"(\n"+calc_indent(indent+3)+"address = " + address::from_hash(output.address) +
				"\n"+calc_indent(indent+3)+"amount = " + display_coins(output.amount) + 
				(output.msg.length() > 0 ? ("\n"+calc_indent(indent+3)+"message = " + output.msg) : "") +
				"\n"+calc_indent(indent+2)+")";
	}

	return out + "\n"+calc_indent(indent+1)+"]\n"+calc_indent(indent)+")\n";
}

std::string Transaction::get_pubkey()
{
	if(inputs.size() == 0)
	{
		return "";
	}

	return inputs.begin()->key_pub;
}
