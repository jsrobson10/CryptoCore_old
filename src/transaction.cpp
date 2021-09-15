
#include "address.hpp"
#include "transaction.hpp"
#include "helpers.hpp"
#include "sig.hpp"
#include "web.hpp"
#include "config.hpp"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <unistd.h>

#include <iostream>
#include <thread>
#include <cstring>
#include <atomic>
#include <mutex>

//#define NO_MINING

std::atomic<uint64_t> transaction_hashrate(0);

Transaction::Transaction()
{
	pos = -1;
	work = 0;
	created = get_micros();
	received = created;
	finalized = false;
	valid = true;
}

Transaction::Transaction(Transaction& t)
{
	pos = t.pos;
	work = t.work;
	created = t.created;
	received = t.received;
	finalized = t.finalized;
	valid = t.valid;
	token = t.token;
	txnoise = t.txnoise;
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

Transaction::Transaction(const char* bytes, size_t len, bool trusted)
{
	pos = -1;
	finalized = true;
	valid = true;

	// must be bigger than this
	if(len < 348)
	{
		valid = false;
		return;
	}

	txid = std::string(bytes, 32); bytes += 32;
	txnoise = std::string(bytes, 32); bytes += 32;
	token = std::string(bytes, 32); bytes += 32;

	verifies[0] = std::string(bytes, 64); bytes += 64;
	verifies[1] = std::string(bytes, 64); bytes += 64;

	created = get_netul(bytes); bytes += 8;
	work = get_netul(bytes); bytes += 8;

	uint16_t inputs_len = get_netus(bytes); bytes += 2;
	uint16_t outputs_len = get_netus(bytes); bytes += 2;
	uint64_t size = 348 + inputs_len * (SIG_LEN_PUBKEY + 84) + outputs_len * 74;

	// must be bigger than this
	if(len < size)
	{
		valid = false;
		return;
	}

	// add the inputs
	for(int i = 0; i < inputs_len; i++)
	{
		Transaction::Input input;

		input.pubkey = std::string(bytes, SIG_LEN_PUBKEY); bytes += SIG_LEN_PUBKEY;
		input.prev = std::string(bytes, 32); bytes += 32;
		input.balance = get_netul(bytes); bytes += 8;
		input.amount = get_netul(bytes); bytes += 8;
		
		uint16_t sources_len = get_netus(bytes); bytes += 2;
		size += sources_len * 32;

		if(len < size)
		{
			valid = false;
			return;
		}

		for(int j = 0; j < sources_len; j++)
		{
			input.sources.push_back(std::string(bytes, 32));
			bytes += 32;
		}
		
		inputs.push_back(input);
	}

	// add the outputs
	for(int i = 0; i < outputs_len; i++)
	{
		Transaction::Output output;

		output.address = std::string(bytes, 32); bytes += 32;
		output.amount = get_netul(bytes); bytes += 8;
		
		uint16_t msg_len = get_netus(bytes); bytes += 2;
		size += msg_len;

		if(len < size)
		{
			valid = false;
			return;
		}

		output.msg = std::string(bytes, msg_len);
		bytes += msg_len;
	}

	// get true positions and timestamps if from
	// a trusted source, like directly from the database
	if(trusted)
	{
		received = get_netul(bytes);
	}

	else
	{
		received = get_micros();
	}

	bytes += 8;

	confirms[0] = std::string(bytes, 32); bytes += 32;
	confirms[1] = std::string(bytes, 32); bytes += 32;
	confirms[2] = std::string(bytes, 32); bytes += 32;

	// add the inputs signatures and next ids
	for(Transaction::Input& input : inputs)
	{
		input.next = std::string(bytes, 32); bytes += 32;

		uint16_t sig_len = get_netus(bytes); bytes += 2;
		size += sig_len;

		if(len < size)
		{
			valid = false;
			return;
		}

		input.sig = std::string(bytes, sig_len);
		bytes += sig_len;
	}

	// add the outputs referenced txids
	for(Transaction::Output& output : outputs)
	{
		output.referenced = std::string(bytes, 32);
		bytes += 32;
	}
}

bool Transaction::is_valid()
{
	return get_errors() == nullptr;
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

	uint64_t total_in = 0;
	uint64_t total_out = 0;
	uint64_t total_b_in = 0;
	
	// calculate total in
	for(Transaction::Input& input : inputs)
	{
		if(has_address(input.address) != 1)
		{
			return "cannot have any address duplicates";
		}
	
		if(input.next == txid || input.prev == txid)
		{
			return "next/prev cannot reference itself";
		}

		uint64_t balance = 0;
		Transaction* prev = web::get_transaction(input.prev);

		// get the last transactions balance
		if(prev != nullptr)
		{
			for(Transaction::Input& in : prev->inputs)
			{
				if(in.address == input.address)
				{
					balance = in.balance;
					break;
				}
			}
			
			delete prev;
		}

		// add all unconfirmed balance
		for(std::string& source_txid : input.sources)
		{
			Transaction* source = web::get_transaction(source_txid);

			for(Transaction::Output& out : source->outputs)
			{
				if(out.address == input.address)
				{
					balance += out.amount;
				}
			}

			delete source;
		}

		if(input.balance > balance)
		{
			return "invalid input balance";
		}

		uint64_t change = balance - input.balance;
		
		if(total_in + change < total_in || total_b_in + input.amount < total_b_in)
		{
			return "invalid input balance";
		}

		total_in += change;
		total_b_in += input.amount;
	}
	
	// calculate total out
	for(Transaction::Output& output : outputs)
	{
		if(total_out + output.amount < total_out)
		{
			return "invalid output balance";
		}
		
		total_out += output.amount;
		
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
	if(total_in != total_out)
	{
		return "total in does not match total out";
	}

	// total in mismatch
	if(total_in != total_b_in)
	{
		return "total in does not match calculated in";
	}

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
	

	// check for invalid txid
	
	size_t tx_len = serialize_t_len();

	// 1 MB limit
	if(tx_len > 1048576)
	{
		return "transaction too large";
	}

	char* tx = new char[tx_len];
	serialize_t(tx);

	// get hash without txid
	char txid_c[32];
	memcpy(txid_c, tx + 40, 32);
	memset(tx + 40, 0, 32);

	char digest_c[32];
	SHA256((uint8_t*)tx, tx_len, (uint8_t*)digest_c);
	
	if(!bytes_are_equal(digest_c, txid_c, 32))
	{
		delete[] tx;
		return "invalid txid";
	}

	memcpy(tx + 40, txid_c, 32);
	SHA256((uint8_t*)tx, tx_len, (uint8_t*)digest_c);
	
	delete[] tx;

#ifndef NO_MINING
	if(digest_c[0] != 0x00 || digest_c[1] != 0x00 || digest_c[2] != 0x00)
	{
		return "not enough work";
	}
#endif

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

bool Transaction::is_confirmed()
{
	return (count_confirms() > 1);
}

size_t Transaction::serialize_t_len()
{
	size_t len_inputs = 0;
	size_t len_outputs = 0;

	if(finalized)
	{
		for(Transaction::Input& input : inputs)
		{
			len_inputs += 50 + SIG_LEN_PUBKEY + input.sources.size() * 32;
		}
	}

	else
	{
		for(Transaction::InputNew input : inputs_new)
		{
			len_inputs += 50 + SIG_LEN_PUBKEY + input.sources.size() * 32;
		}
	}

	for(Transaction::Output& output : outputs)
	{
		len_outputs += 42 + output.msg.length();
	}

	return 244 + len_inputs + len_outputs;
}

char* Transaction::serialize_t(char* data)
{
	memcpy_if(data, txid.c_str(), '\0', 32, txid.length() == 32); data += 32;
	memcpy_if(data, txnoise.c_str(), '\0', 32, txnoise.length() == 32); data += 32;
	memcpy_if(data, token.c_str(), '\0', 32, token.length() == 32); data += 32;
	memcpy_if(data, verifies[0].c_str(), '\0', 64, verifies[0].length() == 64); data += 64;
	memcpy_if(data, verifies[1].c_str(), '\0', 64, verifies[1].length() == 64); data += 64;

	put_netul(data, created); data += 8;
	put_netul(data, work); data += 8;
	
	uint16_t size_in = finalized ? inputs.size() : inputs_new.size();
	uint16_t size_out = outputs.size();

	put_netus(data, size_in); data += 2;
	put_netus(data, size_out); data += 2;

	// write finalized inputs
	
	if(finalized)
	{
		for(Transaction::Input& input : inputs)
		{
			memcpy_if(data, input.pubkey.c_str(), '\0', SIG_LEN_PUBKEY, input.pubkey.length() == SIG_LEN_PUBKEY); data += SIG_LEN_PUBKEY;
			memcpy_if(data, input.prev.c_str(), '\0', 32, input.prev.length() == 32); data += 32;
			put_netul(data, input.balance); data += 8;
			put_netul(data, input.amount); data += 8;
			put_netus(data, input.sources.size() & 65535); data += 2;

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
		for(Transaction::InputNew& input : inputs_new)
		{
			std::string pubkey = sig::getpubkey(input.prikey);

			memcpy_if(data, pubkey.c_str(), '\0', SIG_LEN_PUBKEY, pubkey.length() == SIG_LEN_PUBKEY); data += SIG_LEN_PUBKEY;
			memcpy_if(data, input.prev.c_str(), '\0', 32, input.prev.length() == 32); data += 32;
			put_netul(data, input.balance); data += 8;
			put_netul(data, input.amount); data += 8;
			put_netus(data, input.sources.size() & 65535); data += 2;

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
		memcpy_if(data, output.address.c_str(), '\0', 32, output.address.length() == 32); data += 32;
		put_netul(data, output.amount); data += 8;

		uint16_t msg_len = output.msg.length() & 65535;

		if(output.msg.length() > msg_len)
		{
			msg_len = 65535;
		}

		put_netus(data, msg_len); data += 2;
		memcpy(data, output.msg.c_str(), msg_len);
		data += msg_len;
	}

	return data;
}

size_t Transaction::serialize_len()
{
	finalize();
	
	size_t len_inputs = 0;
	size_t len_outputs = 0;

	for(Transaction::Input& input : inputs)
	{
		len_inputs += 84 + SIG_LEN_PUBKEY + input.sources.size() * 32 + input.sig.length() & 65535;
	}

	for(Transaction::Output& output : outputs)
	{
		len_outputs += 74 + output.msg.length();
	}

	return 348 + len_inputs + len_outputs;
}

char* Transaction::serialize(char* data)
{
	finalize();
	
	data = serialize_t(data);

	put_netul(data, received); data += 8;

	memcpy_if(data, confirms[0].c_str(), '\0', 32, confirms[0].length() == 32); data += 32;
	memcpy_if(data, confirms[1].c_str(), '\0', 32, confirms[1].length() == 32); data += 32;
	memcpy_if(data, confirms[2].c_str(), '\0', 32, confirms[2].length() == 32); data += 32;
	
	for(Transaction::Input& input : inputs)
	{
		uint16_t sig_len = input.sig.length() & 65535;

		memcpy_if(data, input.next.c_str(), '\0', 32, input.next.length() == 32); data += 32;
		put_netus(data, sig_len); data += 2;
		memcpy(data, input.sig.c_str(), sig_len);
		data += sig_len;
	}

	for(Transaction::Output& output : outputs)
	{
		memcpy_if(data, output.referenced.c_str(), '\0', 32, output.referenced.length() == 32);
		data += 32;
	}

	return data;
}

struct finalize_data
{
	char verify[128] = {0};
};

static void finalize_worker(volatile bool* running, bool* status, char* tx, size_t txlen, std::atomic<finalize_data>* data, std::atomic<uint64_t>* hashrate)
{
	// generate the txid
	
	char txhash_c[32];
	uint64_t hashrate_c = 0;
	uint64_t us_inc = get_micros();
	
	RAND_bytes((uint8_t*)(tx + 8), 32);

	// load everything from the parent thread
	finalize_data gdata = data->load();
	memcpy(tx + 72,  gdata.verify, 128);
	put_netul(tx, us_inc);

	// only run while other threads are running
	//
	// i don't care if theres some memory race
	// UB from reading this as it's written, 
	// because it doesn't really change much if
	// this is interperated as true or false when
	// it's in the middle of being written to.
	//
	// making this an atomic variable would just
	// be much less efficiency from wasted CPU
	// cycles just to prevent memory race UB
	// that i don't actually care about. 
	while(*running)
	{
		uint64_t us_now = get_micros();

		if(us_now - us_inc >= 1000000)
		{
			// the "main thread" sends us up to date
			// transaction data every second
			us_inc += 1000000;
			finalize_data gdata = data->load();
			memcpy(tx + 72,  gdata.verify, 128);
			put_netul(tx, us_now);

			// i care about UB memory race protection
			// here because this bit of code is
			// only being run every second, and i
			// want accurate hashrate reporting.
			*hashrate += hashrate_c;
			hashrate_c = 0;
		}

		// increment local hashrate
		hashrate_c += 1;

		// first clear out the txid to get the txid
		memset(tx + 40, 0, 32);

		// generate the txid with the seed included
		SHA256((uint8_t*)tx, txlen, (uint8_t*)(tx + 40));

		// check if enough work has been done
		SHA256((uint8_t*)tx, txlen, (uint8_t*)txhash_c);

#ifndef NO_MINING
		if(txhash_c[0] == 0x00 && txhash_c[1] == 0x00 && txhash_c[2] == 0x00)
#endif
		{
			// tell every thread to quit
			*running = false;
			*status = true;
			break;
		}

		// try again with new data
		memcpy(tx + 8, txhash_c, 32);
	}
}

void Transaction::finalize()
{
	// finalize can only be called once
	if(finalized)
	{
		return;
	}
	
	std::string txhash;

	// do proof of work on multiple threads
	{
		// only 1 proof of work can be calculated at a time
		// this is to help prevent issues with related transactions
		// and one being rejected
		static std::mutex mtx_pow;
		mtx_pow.lock();

		size_t txlen = serialize_t_len();
		char* tx = new char[txlen];

		serialize_t(tx);

		std::thread* workers = new std::thread[config::workers];
		char* txbucket = new char[txlen * config::workers];
		bool* status = new bool[config::workers];
		std::atomic<finalize_data> data;
		std::atomic<uint64_t> hashrate_a(0);
		volatile bool running = true;
		bool hashrate_done = false;
		bool do_update = true;
		
		{
			Transaction *t1, *t2;
			finalize_data ndata;

			web::get_edge_nodes(t1, t2);
			
			if(t1 == nullptr || t2 == nullptr)
			{
				do_update = false;
				memset(ndata.verify, 0, 96);
				data.store(ndata);
			}

			else
			{
				std::string t1_hash = t1->get_hash();
				std::string t2_hash = t2->get_hash();

				memcpy(ndata.verify,      t1->txid.c_str(), 32);
				memcpy(ndata.verify + 32, t1_hash.c_str(),  32);
				memcpy(ndata.verify + 64, t2->txid.c_str(), 32);
				memcpy(ndata.verify + 96, t2_hash.c_str(),  32);

				data.store(ndata);

				delete t1;
				delete t2;
			}
		}

		// start all the workers
		for(int i = 0; i < config::workers; i++)
		{
			memcpy(txbucket + i * txlen, tx, txlen);

			status[i] = false;
			workers[i] = std::thread(&finalize_worker, &running, &status[i], &txbucket[i * txlen], txlen, &data, &hashrate_a);
		}

		uint64_t us_inc = get_micros();
		uint64_t us_now;

		// sleep until done
		while(running)
		{
			usleep(1000);
			us_now = get_micros();

			// every second
			if(us_now - us_inc >= 1000000 && do_update)
			{
				us_inc += 1000000;

				// get new edge nodes and update the edge pos
				Transaction *t1, *t2;
				finalize_data ndata;

				web::get_edge_nodes(t1, t2);
				std::string t1_hash = t1->get_hash();
				std::string t2_hash = t2->get_hash();

				memcpy(ndata.verify,      t1->txid.c_str(), 32);
				memcpy(ndata.verify + 32, t1_hash.c_str(),  32);
				memcpy(ndata.verify + 64, t2->txid.c_str(), 32);
				memcpy(ndata.verify + 96, t2_hash.c_str(),  32);

				data.store(ndata);

				// get the hashrate
				transaction_hashrate.store(hashrate_a.exchange(0));
			
				delete t1;
				delete t2;
			}
		}

		// hashrate is 0 since we're
		// not mining anything anymore
		transaction_hashrate.store(0);
		
		// wait until all the workers are closed
		for(int i = 0; i < config::workers; i++)
		{
			workers[i].join();
		}

		delete[] tx;

		// find the good transaction bucket
		for(int i = 0; i < config::workers; i++)
		{
			if(status[i])
			{
				tx = &txbucket[i * txlen];
				break;
			}
		}

		// set the generated data
		created = get_netul(tx);
		txnoise = std::string(tx + 8, 32);
		txid = std::string(tx + 40, 32);
		
		verifies[0] = std::string(tx + 72, 64);
		verifies[1] = std::string(tx + 136, 64);

		char txhash_c[32];
		SHA256((uint8_t*)tx, txlen, (uint8_t*)txhash_c);
		txhash = std::string(txhash_c, 32);

		delete[] txbucket;
		delete[] status;
		delete[] workers;

		mtx_pow.unlock();
	}

	// convert all new inputs into inputs
	for(Transaction::InputNew& input_new : inputs_new)
	{
		Transaction::Input input;

		input.amount = input_new.amount;
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

std::string Transaction::get_hash()
{
	char txhash_c[32];

	size_t txlen = serialize_t_len();
	char* tx = new char[txlen];

	serialize_t(tx);
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

void Transaction::add_input(std::string prikey, uint64_t amount, uint64_t balance, std::string prev, const std::list<std::string>& sources)
{
	if(finalized) return;

	Transaction::InputNew input;
	
	input.address = address::fromprikey(prikey);
	input.sources = std::list<std::string>(sources);
	input.prikey = prikey;
	input.balance = balance;
	input.amount = amount;
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

	if(!is_id_unset(txid)) root["txid"] = address::fromhash(txid, ADDR_TRANSACTION);
	if(!is_id_unset(txnoise)) root["txnoise"] = to_hex(txnoise);
	if(!is_id_unset(txid)) root["txhash"] = to_hex(get_hash());
	root["created"] = std::to_string(created);
	root["received"] = std::to_string(received);
	root["total"] = std::to_string(get_total());
	root["confirmed"] = is_confirmed();
	root["finalized"] = finalized;
	root["valid"] = error ? false : true;
	if(error) root["error"] = std::string(error);
	
	int at = 0;

	for(int i = 0; i < 2; i++)
	{
		if(!is_id_unset(verifies[i].substr(0, 32)))
		{
			root["verifies"][at] = address::fromhash(verifies[i], ADDR_TRANSACTION);
			at += 1;
		}
	}

	at = 0;

	for(int i = 0; i < 3; i++)
	{
		if(!is_id_unset(confirms[i]))
		{
			root["confirms"][at] = address::fromhash(confirms[i], ADDR_TRANSACTION);
			at += 1;
		}
	}

	at = 0;

	if(finalized)
	{
		for(Input& input : inputs)
		{
			Json::Value input_j;

			input_j["address"] = address::fromhash(input.address, ADDR_DEPOSIT);
			input_j["pubkey"] = to_hex(input.pubkey);
			input_j["sig"] = to_hex(input.sig);
			input_j["balance"] = std::to_string(input.balance);
			input_j["amount"] = std::to_string(input.amount);
			if(!is_id_unset(input.prev)) input_j["prev"] = address::fromhash(input.prev, ADDR_TRANSACTION);
			if(!is_id_unset(input.next)) input_j["next"] = address::fromhash(input.next, ADDR_TRANSACTION);

			Json::Value sources_j;
			int sources_i = 0;

			for(std::string& source : input.sources)
			{
				sources_j[sources_i] = address::fromhash(source, ADDR_TRANSACTION);
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

			input_j["address"] = address::fromhash(input.address, ADDR_DEPOSIT);
			input_j["pubkey"] = to_hex(sig::getpubkey(input.prikey));
			input_j["balance"] = std::to_string(input.balance);
			input_j["amount"] = std::to_string(input.amount);
			if(!is_id_unset(input.prev)) input_j["prev"] = address::fromhash(input.prev, ADDR_TRANSACTION);
			if(!is_id_unset(input.next)) input_j["next"] = address::fromhash(input.next, ADDR_TRANSACTION);

			Json::Value sources_j;
			int sources_i = 0;

			for(std::string& source : input.sources)
			{
				sources_j[sources_i] = address::fromhash(source, ADDR_TRANSACTION);
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

		output_j["address"] = address::fromhash(output.address, ADDR_DEPOSIT);
		output_j["amount"] = std::to_string(output.amount);

		if(output.msg.length() > 0)
		{
			output_j["message"] = output.msg;
		}

		root["outputs"][at] = output_j;
		at += 1;
	}

	return root;
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

int Transaction::count_confirms()
{
	int c = 0;

	for(int i = 0; i < 3; i++)
	{
		if(!is_id_unset(confirms[i]))
		{
			c += 1;
		}
	}

	return c;
}

