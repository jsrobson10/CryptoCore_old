
#include "address.hpp"
#include "transaction.hpp"
#include "helpers.hpp"
#include "sig.hpp"

#include <openssl/sha.h>
#include <openssl/rand.h>

#include <cstring>

/*
 * 
 * Transaction binary format:
 *
 * [created, 8]
 * [txid, 32]
 * [verify1, 32]
 * [verify2, 32]
 * [inputs, 1]
 * [outputs, 1]
 * (inputs)
 * {
 *   [prev, 32]
 *   [pubkey, SIG_LEN_PUBKEY]
 *   [balance, 8]
 *   [sources, 2]
 *   (sources)
 *   {
 *     [txid, 32]
 *   }
 * }
 * (outputs)
 * {
 *	 [address, 20]
 *	 [amount, 8]
 *	 [msglen, 1]
 *	 [msg, msglen]
 * }
 * !
 * [confirm1, 32]
 * [confirm2, 32]
 * [confirm3, 32]
 * (inputs)
 * {
 *	 [next, 32]
 *	 [siglen, 2]
 *	 [sig, siglen]
 * }
 *
 */

Transaction::Transaction()
{
	created = get_micros();
	received = created;
	verified = true;
	confirmed = false;
	finalized = false;
	valid = true;
	pos = 0;
}

Transaction::Transaction(Transaction& t)
{
	verified = t.verified;
	created = t.created;
	received = t.received;
	confirmed = t.confirmed;
	finalized = t.finalized;
	valid = t.valid;
	txid = t.txid;

	verifies[0] = t.verifies[0];
	verifies[1] = t.verifies[1];
	confirms[0] = t.confirms[0];
	confirms[1] = t.confirms[1];
	confirms[2] = t.confirms[2];

	inputs_new = std::list<Transaction::InputNew>(t.inputs_new);
	inputs = std::list<Transaction::Input>(t.inputs);
	outputs = std::list<Transaction::Output>(t.outputs);
}

Transaction::Transaction(const char* bytes, size_t len, const char** bytes_n, size_t* len_n)
{
	received = get_micros();
	created = received;
	verified = false;
	confirmed = false;
	finalized = true;
	valid = true;

	if(len < 202)
	{
		valid = false;
		return;
	}

	created = get_netul(bytes);
	txid = std::string(bytes + 8, 32);
	pos = get_id_data(bytes + 8);

	verifies[0] = std::string(bytes + 40, 32);
	verifies[1] = std::string(bytes + 72, 32);
	
	const char* end = bytes + len;
	
	int inputs_len = ((unsigned char*)bytes)[104];
	int outputs_len = ((unsigned char*)bytes)[105];

	bytes += 106;
	len -= 106;

	// add the inputs
	for(int i = 0; i < inputs_len; i++)
	{
		Transaction::Input input;

		input.prev = std::string(bytes, 32);
		input.pubkey = std::string(bytes + 32, SIG_LEN_PUBKEY);
		input.balance = get_netul(bytes + 32 + SIG_LEN_PUBKEY);
		input.address = address::frompubkey(input.pubkey);
		inputs.push_back(input);

		int c = 42 + SIG_LEN_PUBKEY;

		bytes += c;
		len -= c;

		uint16_t sources_len = get_netus(bytes - 2);
		
		for(int j = 0; j < sources_len; j++)
		{
			input.sources.push_back(std::string(bytes, 32));

			bytes += 32;
			len -= 32;
		}
	}

	// add the outputs
	for(int i = 0; i < outputs_len; i++)
	{
		Transaction::Output output;

		uint8_t msglen = (uint8_t)(bytes[28]);

		output.address = std::string(bytes, 20);
		output.amount = get_netul(bytes + 20);
		output.msg = std::string(bytes + 29, msglen);
		outputs.push_back(output);

		int c = 29 + msglen;

		bytes += c;
		len -= c;
	}
	
	confirms[0] = std::string(bytes, 32);
	confirms[1] = std::string(bytes + 32, 32);
	confirms[2] = std::string(bytes + 64, 32);

	bytes += 96;
	len -= 96;

	// add the inputs signatures and next ids
	for(Transaction::Input& input : inputs)
	{
		uint16_t o = get_netus(bytes + 32);

		input.next = std::string(bytes, 32);
		input.sig = std::string(bytes + 34, o);

		bytes += 34 + o;
		len -= 34 + o;
	}

	// send back how many bytes were read
	if(bytes_n != nullptr)
	{
		*bytes_n = bytes;
	}

	if(len_n != nullptr)
	{
		*len_n = len;
	}
}

bool Transaction::is_valid()
{
	return get_errors() == nullptr;
}

bool Transaction::has_prikey()
{
	return inputs_new.size() != 0;
}

std::string Transaction::get_prikey()
{
	return inputs_new.begin()->prikey;
}

bool Transaction::is_verified()
{
	return verified;
}

void Transaction::set_verified()
{
	verified = true;
}

int Transaction::has_address(std::string address)
{
	int count = 0;
	
	if(finalized)
	{
		for(Transaction::Input& input : inputs)
		{
			if(input.address == address)
			{
				count += 1;
			}
		}
	}

	else
	{
		for(Transaction::InputNew& input : inputs_new)
		{
			if(input.address == address)
			{
				count += 1;
			}
		}
	}

	for(Transaction::Output& output : outputs)
	{
		if(output.address == address)
		{
			count += 1;
		}
	}

	return count;
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

	if(pos > 1)
	{
		uint64_t total_in = 0;
		uint64_t total_out = 0;
	
		// calculate total in
		for(Transaction::Input& input : inputs)
		{
			//total_in += input.balance;
	
			if(has_address(input.address) != 1)
			{
				return "cannot have any address duplicates";
			}
	
			if(input.next == txid || input.prev == txid)
			{
				return "next/prev cannot reference itself";
			}
		}
	
		// calculate total out
		for(Transaction::Output& output : outputs)
		{
			//total_out += output.amount;
			
			if(has_address(output.address) != 1)
			{
				return "cannot have any address duplicates";
			}
		}
	
		// cant transfer zero coins
		if(total_out == 0)
		{
			return "cannot transfer zero coins";
		}
	
		// total in/out mismatch
		//if(total_in != total_out)
		//{
		//	return "total in does not match total out";
		//}
	
		// check confirms and verifies for duplicates or self references
		
		for(int i = 0; i < 5; i++)
		{
			std::string id_i = i < 3 ? verifies[i] : confirms[i-2];
			int count = 0;
	
			if(is_id_unset(id_i))
			{
				continue;
			}
	
			if(id_i == txid)
			{
				return "verify/confirm id cannot reference itself";
			}
	
			for(int j = 0; j < 5; j++)
			{
				std::string id_j = j < 3 ? verifies[j] : confirms[j-2];
	
				if(id_i == id_j)
				{
					count += 1;
				}
			}
	
			if(count > 1)
			{
				return "verify/confirm id contains duplicates";
			}
		}
	}

	// check for invalid signatures
	
	size_t tx_len = serialize_t_len();
	char* tx = new char[tx_len];
	serialize_t(tx);

	char digest_c[32];
	SHA256((unsigned char*)tx, tx_len, (unsigned char*)digest_c);

	delete[] tx;

	std::string digest(digest_c, 32);

	for(Transaction::Input& input : inputs)
	{
		if(!sig::verify(input.pubkey, digest, input.sig))
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
	size_t len_inputs = 0;
	size_t len_outputs = 0;

	if(finalized)
	{
		for(Transaction::Input& input : inputs)
		{
			len_inputs += 42 + SIG_LEN_PUBKEY + input.sources.size() * 32;
		}
	}

	else
	{
		for(Transaction::InputNew input : inputs_new)
		{
			len_inputs += 42 + SIG_LEN_PUBKEY + input.sources.size() * 32;
		}
	}

	for(Transaction::Output& output : outputs)
	{
		len_outputs += output.msg.length() + 29;
	}

	return 106 + len_inputs + len_outputs;
}

char* Transaction::serialize_t(char* data)
{
	put_netul(data, created);
	
	memcpy(data + 8, txid.c_str(), 32);
	memcpy_if(data + 40, verifies[0].c_str(), '\0', 32, verifies[0].length() == 32);
	memcpy_if(data + 72, verifies[1].c_str(), '\0', 32, verifies[1].length() == 32);

	data[105] = outputs.size();

	// write finalized inputs
	
	if(finalized)
	{
		data[104] = (char)inputs.size();
		data += 106;
		
		for(Transaction::Input& input : inputs)
		{
			memcpy_if(data, input.prev.c_str(), '\0', 32, input.prev.length() == 32);
			memcpy(data + 32, input.pubkey.c_str(), SIG_LEN_PUBKEY);
			put_netul(data + 32 + SIG_LEN_PUBKEY, input.balance);

			data += 42 + SIG_LEN_PUBKEY;
			put_netus(data - 2, input.sources.size() & 65535);

			for(std::string& source : input.sources)
			{
				memcpy(data, source.c_str(), 32);
				data += 32;
			}
		}
	}

	// write unfinalized inputs

	else
	{
		data[104] = (char)inputs_new.size();
		data += 106;

		for(Transaction::InputNew& input : inputs_new)
		{
			std::string pubkey = sig::getpubkey(input.prikey);

			memcpy_if(data, input.prev.c_str(), '\0', 32, input.prev.length() == 32);
			memcpy(data + 32, pubkey.c_str(), SIG_LEN_PUBKEY);
			put_netul(data + 32 + SIG_LEN_PUBKEY, input.balance);

			data += 42 + SIG_LEN_PUBKEY;
			put_netus(data - 2, input.sources.size() & 65535);

			for(std::string& source : input.sources)
			{
				memcpy(data, source.c_str(), 32);
				data += 32;
			}
		}
	}

	// write outputs

	for(Transaction::Output& output : outputs)
	{
		uint8_t msg_len = output.msg.length() & 255;

		if(output.msg.length() > msg_len)
		{
			msg_len = 255;
		}

		memcpy(data, output.address.c_str(), 20);
		put_netul(data + 20, output.amount);

		data[28] = msg_len;

		memcpy(data + 29, output.msg.c_str(), msg_len);
		data += 29 + msg_len;
	}

	return data;
}

size_t Transaction::serialize_len()
{
	finalize();
	
	size_t len = serialize_t_len() + 96;

	for(Transaction::Input& input : inputs)
	{
		len += 34 + input.sig.length();
	}

	return len;
}

char* Transaction::serialize(char* data)
{
	finalize();
	
	data = serialize_t(data);

	memcpy_if(data, confirms[0].c_str(), '\0', 32, confirms[0].length() == 32);
	memcpy_if(data + 32, confirms[1].c_str(), '\0', 32, confirms[1].length() == 32);
	memcpy_if(data + 64, confirms[2].c_str(), '\0', 32, confirms[2].length() == 32);
	
	data += 96;

	for(Transaction::Input& input : inputs)
	{
		uint16_t sig_len = input.sig.length() & 65535;

		memcpy_if(data, input.next.c_str(), '\0', 32, input.next.length() == 32);
		put_netus(data + 32, sig_len);
		memcpy(data + 34, input.sig.c_str(), sig_len);
		data += 34 + sig_len;
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

	// generate the txid
	
	char txid_c[32];

	RAND_bytes((uint8_t*)txid_c, 32);
	set_id_data(txid_c, pos);
	txid = std::string(txid_c, 32);

	// get the hash of the transaction not including signatures
	
	char txhash_c[32];

	size_t txlen = serialize_t_len();
	char* tx = new char[txlen];

	serialize_t(tx);
	SHA256((unsigned char*)tx, txlen, (unsigned char*)txhash_c);

	std::string txhash(txhash_c, 32);

	delete[] tx;

	// convert all new inputs into inputs
	for(Transaction::InputNew& input_new : inputs_new)
	{
		Transaction::Input input;

		input.balance = input_new.balance;
		input.pubkey = sig::getpubkey(input_new.prikey);
		input.sources = std::list<std::string>(input_new.sources);
		input.sig = sig::sign(input_new.prikey, txhash);
		input.address = input_new.address;
		input.next = input_new.next;
		input.prev = input_new.prev;

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

	for(Transaction::Output& output : outputs)
	{
		total += output.amount;
	}

	return total;
}

uint64_t Transaction::get_created()
{
	return created;
}

uint64_t Transaction::get_received()
{
	return received;
}

uint64_t Transaction::get_pos()
{
	return pos;
}

void Transaction::add_input(std::string prikey, uint64_t balance, std::string prev, const std::list<std::string>& sources)
{
	if(finalized) return;

	Transaction::InputNew input;
	
	input.address = address::fromprikey(prikey);
	input.sources = std::list<std::string>(sources);
	input.prikey = prikey;
	input.balance = balance;
	input.prev = prev;

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

	output.address = address;
	output.amount = amount;
	output.msg = msg;

	outputs.push_back(output);
}

Json::Value Transaction::to_json()
{
	const char* error = get_errors();
	Json::Value root;

	if(!is_id_unset) root["txid"] = to_hex(txid);
	root["created"] = created;
	root["received"] = received;
	root["total"] = get_total();
	root["confirmed"] = is_confirmed();
	root["finalized"] = is_finalized();
	root["valid"] = error ? false : true;
	if(error) root["error"] = std::string(error);
	
	int at = 0;

	for(int i = 0; i < 2; i++)
	{
		if(!is_id_unset(verifies[i]))
		{
			root["verifies"][at] = verifies[i];
			at += 1;
		}
	}

	at = 0;

	for(int i = 0; i < 3; i++)
	{
		if(!is_id_unset(confirms[i]))
		{
			root["confirms"][at] = confirms[i];
			at += 1;
		}
	}

	at = 0;

	if(is_finalized())
	{
		for(Input& input : inputs)
		{
			Json::Value input_j;

			input_j["address"] = address::fromhash(input.address);
			input_j["pubkey"] = to_hex(input.pubkey);
			input_j["sig"] = to_hex(input.sig);
			input_j["balance"] = display_coins(input.balance);
			if(!is_id_unset(input.prev)) input_j["prev"] = to_hex(input.prev);
			if(!is_id_unset(input.next)) input_j["next"] = to_hex(input.next);

			Json::Value sources_j;
			int sources_i = 0;

			for(std::string& source : input.sources)
			{
				sources_j[sources_i] = to_hex(source);
				sources_i += 1;
			}

			input_j["sources"] = sources_j;
			root["inputs"][at] = input_j;
			at += 1;
		}
	}

	else
	{
		for(InputNew& input : inputs_new)
		{
			Json::Value input_j;

			input_j["address"] = address::fromhash(input.address);
			input_j["pubkey"] = to_hex(sig::getpubkey(input.prikey));
			input_j["balance"] = display_coins(input.balance);
			if(!is_id_unset(input.prev)) input_j["prev"] = to_hex(input.prev);
			if(!is_id_unset(input.next)) input_j["next"] = to_hex(input.next);

			Json::Value sources_j;
			int sources_i = 0;

			for(std::string& source : input.sources)
			{
				sources_j[sources_i] = to_hex(source);
				sources_i += 1;
			}

			input_j["sources"] = sources_j;
			root["inputs"][at] = input_j;
			at += 1;
		}
	}

	at = 0;

	for(Output& output : outputs)
	{
		Json::Value output_j;

		output_j["address"] = address::fromhash(output.address);
		output_j["amount"] = output.amount;

		if(output.msg.length() > 0)
		{
			output_j["message"] = output.msg;
		}

		root["outputs"][at] = output_j;
		at += 1;
	}

	return root;
}

std::string Transaction::to_string(int indent)
{
	const char* error = get_errors();
	
	std::string out = calc_indent(indent)+"Transaction (" +
			"\n"+calc_indent(indent+1)+"txid = " + (is_id_unset(txid) ? "unset" : to_hex(txid)) +
			"\n"+calc_indent(indent+1)+"created = " + std::to_string(created) + 
			"\n"+calc_indent(indent+1)+"received = " + std::to_string(received) +
			"\n"+calc_indent(indent+1)+"total = " + display_coins(get_total()) +
			"\n"+calc_indent(indent+1)+"confirmed = " + (is_confirmed() ? "1" : "0") +
			"\n"+calc_indent(indent+1)+"finalized = " + (is_finalized() ? "1" : "0") +
			"\n"+calc_indent(indent+1)+"valid = " + (error ? ("0\n"+calc_indent(indent+1)+"error = " + std::string(error)) : "1") +
			"\n"+calc_indent(indent+1)+"verifies = [";

	for(int i = 0; i < 2; i++)
	{
		if(!is_id_unset(verifies[i]))
		{
			out += "\n"+calc_indent(indent+2)+to_hex(verifies[i]);
		}
	}

	out += "\n"+calc_indent(indent+1)+"]\n"+calc_indent(indent+1)+"confirms = [";

	for(int i = 0; i < 3; i++)
	{
		if(!is_id_unset(confirms[i]))
		{
			out += "\n"+calc_indent(indent+2)+to_hex(confirms[i]);
		}
	}

	out += "\n"+calc_indent(indent+1)+"]\n"+calc_indent(indent+1)+"inputs = [";

	if(is_finalized())
	{
		for(Transaction::Input& input : inputs)
		{
			out += "\n"+calc_indent(indent+2)+"("+
					"\n"+calc_indent(indent+3)+"address = " + address::fromhash(input.address) +
					"\n"+calc_indent(indent+3)+"pubkey = " + to_hex(input.pubkey.c_str(), 16) + "..." + to_hex(input.pubkey.c_str() + input.pubkey.length() - 16, 16) +
					"\n"+calc_indent(indent+3)+"sig = " + to_hex(input.sig.c_str(), 16) + "..." + to_hex(input.sig.c_str() + input.sig.length() - 16, 16) +
					"\n"+calc_indent(indent+3)+"balance = " + display_coins(input.balance) +
					"\n"+calc_indent(indent+3)+"prev = " + (is_id_unset(input.prev) ? "unset" : to_hex(input.prev)) +
					"\n"+calc_indent(indent+3)+"next = " + (is_id_unset(input.next) ? "unset" : to_hex(input.next)) +
					"\n"+calc_indent(indent+3)+"sources = [";

			for(std::string& source : input.sources)
			{
				out += "\n"+calc_indent(indent+4)+to_hex(source);
			}

			out += "\n"+calc_indent(indent+3)+"]" +
					"\n"+calc_indent(indent+2)+")";
		}
	}

	else
	{
		for(Transaction::InputNew& input : inputs_new)
		{
			std::string pubkey = sig::getpubkey(input.prikey);

			out += "\n"+calc_indent(indent+2)+"("+
					"\n"+calc_indent(indent+3)+"address = " + address::fromhash(input.address) +
					"\n"+calc_indent(indent+3)+"prikey = " + to_hex(pubkey.c_str(), 16) + "..." + to_hex(pubkey.c_str() + pubkey.length() - 16, 16) +
					"\n"+calc_indent(indent+3)+"amount = " + display_coins(input.balance) +
					"\n"+calc_indent(indent+3)+"prev = " + (is_id_unset(input.prev) ? "unset" : to_hex(input.prev)) +
					"\n"+calc_indent(indent+3)+"next = " + (is_id_unset(input.next) ? "unset" : to_hex(input.next)) +
					"\n"+calc_indent(indent+2)+")";
		}
	}

	out += "\n"+calc_indent(indent+1)+"]\n"+calc_indent(indent+1)+"outputs = [";

	for(Transaction::Output& output : outputs)
	{
		out += "\n"+calc_indent(indent+2)+"("+
				"\n"+calc_indent(indent+3)+"address = " + address::fromhash(output.address) +
				"\n"+calc_indent(indent+3)+"amount = " + display_coins(output.amount) + 
				(output.msg.length() > 0 ? ("\n"+calc_indent(indent+3)+"message = " + output.msg) : "") +
				"\n"+calc_indent(indent+2)+")";
	}

	return out + "\n"+calc_indent(indent+1)+"]\n"+calc_indent(indent)+")\n";
}

int Transaction::count_inputs()
{
	if(finalized)
	{
		return inputs.size();
	}

	else
	{
		return inputs_new.size();
	}
}

int Transaction::count_outputs()
{
	return outputs.size();
}

void Transaction::set_input_next(int pos, std::string next)
{
	int i = 0;
	
	if(finalized)
	{
		for(auto at = inputs.begin(); at != inputs.end(); at++)
		{
			if(i == pos)
			{
				at->next = next;
				break;
			}
		}
	}

	else
	{
		for(auto at = inputs_new.begin(); at != inputs_new.end(); at++)
		{
			if(i == pos)
			{
				at->next = next;
				break;
			}
		}
	}
}

void Transaction::set_verified1(std::string id)
{
	verifies[0] = id;
}

void Transaction::set_verified2(std::string id)
{
	verifies[1] = id;
}

void Transaction::set_pos(uint64_t pos)
{
	this->pos = pos;
}

bool Transaction::add_confirm(std::string id)
{
	for(int i = 0; i < 3; i++)
	{
		if(confirms[i] == id)
		{
			return false;
		}

		if(is_id_unset(confirms[i]))
		{
			confirms[i] = id;

			return true;
		}
	}

	return false;
}

