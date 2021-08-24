
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

/*
 * 
 * Transaction binary format:
 *
 * [created, 8]
 * [txnoise, 32]
 * [txid, 32]
 * [verify1, 64]
 * [verify2, 64]
 * [inputs, 2]
 * [outputs, 2]
 * (inputs)
 * {
 *   [prev, 32]
 *   [pubkey, SIG_LEN_PUBKEY]
 *   [balance, 8]
 *   [amount, 8]
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
 *	 [msglen, 2]
 *	 [msg, msglen]
 * }
 * !
 * [received, 8]
 * [verify1pos, 8]
 * [verify2pos, 8]
 * [confirm1pos, 8]
 * [confirm2pos, 8]
 * [confirm3pos, 8]
 * [confirm1, 32]
 * [confirm2, 32]
 * [confirm3, 32]
 * (inputs)
 * {
 *	 [next, 32]
 *	 [prevpos, 8]
 *	 [nextpos, 8]
 *	 [siglen, 2]
 *	 [sig, siglen]
 * }
 *
 */

std::atomic<uint64_t> transaction_hashrate(0);

Transaction::Transaction()
{
	created = get_micros();
	received = created;
	verified = true;
	finalized = false;
	valid = true;
	pos = 0;

	verifies_pos[0] = 0;
	verifies_pos[1] = 0;
	confirms_pos[0] = 0;
	confirms_pos[1] = 0;
	confirms_pos[2] = 0;
}

Transaction::Transaction(Transaction& t)
{
	pos = t.pos;
	verified = t.verified;
	created = t.created;
	received = t.received;
	finalized = t.finalized;
	valid = t.valid;
	txnoise = t.txnoise;
	txid = t.txid;

	verifies[0] = t.verifies[0];
	verifies[1] = t.verifies[1];
	confirms[0] = t.confirms[0];
	confirms[1] = t.confirms[1];
	confirms[2] = t.confirms[2];

	verifies_pos[0] = t.verifies_pos[0];
	verifies_pos[1] = t.verifies_pos[1];
	confirms_pos[0] = t.confirms_pos[0];
	confirms_pos[1] = t.confirms_pos[1];
	confirms_pos[2] = t.confirms_pos[2];

	inputs_new = std::list<Transaction::InputNew>(t.inputs_new);
	inputs = std::list<Transaction::Input>(t.inputs);
	outputs = std::list<Transaction::Output>(t.outputs);
}

Transaction::Transaction(const char* bytes, size_t len, const char** bytes_n, size_t* len_n, uint64_t txpos, bool trusted)
{
	pos = txpos;
	verified = false;
	finalized = true;
	valid = true;

	if(len < 204)
	{
		valid = false;
		return;
	}

	created = get_netul(bytes);
	txnoise = std::string(bytes + 8, 32);
	txid = std::string(bytes + 40, 32);
	pos = get_id_data(bytes + 40);

	verifies[0] = std::string(bytes + 72, 64);
	verifies[1] = std::string(bytes + 136, 64);
	
	const char* end = bytes + len;
	
	int inputs_len = get_netus(bytes + 200);
	int outputs_len = get_netus(bytes + 202);

	bytes += 204;
	len -= 204;

	// add the inputs
	for(int i = 0; i < inputs_len; i++)
	{
		Transaction::Input input;

		input.prev = std::string(bytes, 32);
		input.pubkey = std::string(bytes + 32, SIG_LEN_PUBKEY);
		input.balance = get_netul(bytes + 32 + SIG_LEN_PUBKEY);
		input.amount = get_netul(bytes + 40 + SIG_LEN_PUBKEY);
		input.address = address::frompubkey(input.pubkey);

		int c = 50 + SIG_LEN_PUBKEY;

		bytes += c;
		len -= c;

		uint16_t sources_len = get_netus(bytes - 2);
		
		for(int j = 0; j < sources_len; j++)
		{
			input.sources.push_back(std::string(bytes, 32));

			bytes += 32;
			len -= 32;
		}
		
		inputs.push_back(input);
	}

	// add the outputs
	for(int i = 0; i < outputs_len; i++)
	{
		Transaction::Output output;

		uint16_t msglen = get_netus(bytes + 28);

		output.address = std::string(bytes, 20);
		output.amount = get_netul(bytes + 20);
		output.msg = std::string(bytes + 30, msglen);
		outputs.push_back(output);

		int c = 30 + msglen;

		bytes += c;
		len -= c;
	}

	// get true positions and timestamps if from
	// a trusted source, like directly from the database
	if(trusted)
	{
		received = get_netul(bytes);

		verifies_pos[0] = get_netul(bytes + 8);
		verifies_pos[1] = get_netul(bytes + 16);
		confirms_pos[0] = get_netul(bytes + 24);
		confirms_pos[1] = get_netul(bytes + 32);
		confirms_pos[2] = get_netul(bytes + 40);
	}

	else
	{
		received = get_micros();

		verifies_pos[0] = -1;
		verifies_pos[1] = -1;
		confirms_pos[0] = -1;
		confirms_pos[1] = -1;
		confirms_pos[2] = -1;
	}
	
	confirms[0] = std::string(bytes + 48, 32);
	confirms[1] = std::string(bytes + 80, 32);
	confirms[2] = std::string(bytes + 112, 32);

	bytes += 144;
	len -= 144;

	// add the inputs signatures and next ids
	for(Transaction::Input& input : inputs)
	{
		uint16_t o = get_netus(bytes + 48);

		input.next = std::string(bytes, 32);
		input.prevpos = get_netul(bytes + 32);
		input.nextpos = get_netul(bytes + 40);
		input.sig = std::string(bytes + 50, o);

		bytes += 50 + o;
		len -= 50 + o;
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

	__uint128_t total_in = 0;
	__uint128_t total_out = 0;
	__uint128_t total_b_in = 0;
	
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

		total_in += balance - input.balance;
		total_b_in += input.amount;
	}
	
	// calculate total out
	for(Transaction::Output& output : outputs)
	{
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

	const uint64_t max_value = 0xffffffffffffffff;

	// overflow
	if(total_in > max_value || total_out > max_value || total_b_in > max_value)
	{
		return "invalid amount";
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
	
	if(		digest_c[0] != txid_c[0] ||
			digest_c[1] != txid_c[1] ||
			digest_c[2] != txid_c[2] ||
			digest_c[4] != txid_c[4] ||
			digest_c[5] != txid_c[5] ||
			digest_c[6] != txid_c[6] ||
			digest_c[8] != txid_c[8] ||
			digest_c[9] != txid_c[9] ||
			digest_c[10] != txid_c[10] ||
			digest_c[12] != txid_c[12] ||
			digest_c[13] != txid_c[13] ||
			digest_c[14] != txid_c[14])
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

bool Transaction::is_finalized()
{
	return this->finalized;
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
		len_outputs += output.msg.length() + 30;
	}

	return 204 + len_inputs + len_outputs;
}

char* Transaction::serialize_t(char* data)
{
	put_netul(data, created);
	
	memcpy(data + 8, txnoise.c_str(), 32);
	memcpy(data + 40, txid.c_str(), 32);
	memcpy_if(data + 72, verifies[0].c_str(), '\0', 64, verifies[0].length() == 64);
	memcpy_if(data + 136, verifies[1].c_str(), '\0', 64, verifies[1].length() == 64);

	put_netus(data + 202, outputs.size());

	// write finalized inputs
	
	if(finalized)
	{
		put_netus(data + 200, inputs.size());
		data += 204;
		
		for(Transaction::Input& input : inputs)
		{
			memcpy_if(data, input.prev.c_str(), '\0', 32, input.prev.length() == 32);
			memcpy(data + 32, input.pubkey.c_str(), SIG_LEN_PUBKEY);
			put_netul(data + 32 + SIG_LEN_PUBKEY, input.balance);
			put_netul(data + 40 + SIG_LEN_PUBKEY, input.amount);

			data += 50 + SIG_LEN_PUBKEY;
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
		put_netus(data + 200, inputs_new.size());
		data += 204;

		for(Transaction::InputNew& input : inputs_new)
		{
			std::string pubkey = sig::getpubkey(input.prikey);

			memcpy_if(data, input.prev.c_str(), '\0', 32, input.prev.length() == 32);
			memcpy(data + 32, pubkey.c_str(), SIG_LEN_PUBKEY);
			put_netul(data + 32 + SIG_LEN_PUBKEY, input.balance);
			put_netul(data + 40 + SIG_LEN_PUBKEY, input.amount);

			data += 50 + SIG_LEN_PUBKEY;
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
		uint16_t msg_len = output.msg.length() & 65535;

		if(output.msg.length() > msg_len)
		{
			msg_len = 65535;
		}

		memcpy(data, output.address.c_str(), 20);
		put_netul(data + 20, output.amount);
		put_netus(data + 28, msg_len);

		memcpy(data + 30, output.msg.c_str(), msg_len);
		data += 30 + msg_len;
	}

	return data;
}

size_t Transaction::serialize_len()
{
	finalize();
	
	size_t len = serialize_t_len() + 144;

	for(Transaction::Input& input : inputs)
	{
		len += 50 + input.sig.length();
	}

	return len;
}

char* Transaction::serialize(char* data)
{
	finalize();
	
	data = serialize_t(data);

	put_netul(data, received);
	put_netul(data + 8, verifies_pos[0]);
	put_netul(data + 16, verifies_pos[1]);
	put_netul(data + 24, confirms_pos[0]);
	put_netul(data + 32, confirms_pos[1]);
	put_netul(data + 40, confirms_pos[2]);

	memcpy_if(data + 48, confirms[0].c_str(), '\0', 32, confirms[0].length() == 32);
	memcpy_if(data + 80, confirms[1].c_str(), '\0', 32, confirms[1].length() == 32);
	memcpy_if(data + 112, confirms[2].c_str(), '\0', 32, confirms[2].length() == 32);
	
	data += 144;

	for(Transaction::Input& input : inputs)
	{
		uint16_t sig_len = input.sig.length() & 65535;

		memcpy_if(data, input.next.c_str(), '\0', 32, input.next.length() == 32);
		put_netul(data + 32, input.prevpos);
		put_netul(data + 40, input.nextpos);
		put_netus(data + 48, sig_len);
		memcpy(data + 50, input.sig.c_str(), sig_len);
		data += 50 + sig_len;
	}

	return data;
}

struct finalize_data
{
	uint64_t pos = 0;
	char verify[128] = {0};
};

static void finalize_worker(volatile bool* running, bool* status, char* tx, size_t txlen, std::atomic<finalize_data>* data, std::atomic<uint64_t>* hashrate)
{
	// generate the txid
	
	char txhash_c[32];
	uint64_t hashrate_c = 0;
	uint64_t us_inc = get_micros() - 1000000;
	uint64_t pos;
	
	RAND_bytes((uint8_t*)(tx + 8), 32);

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
			pos = gdata.pos;

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
		set_id_data(tx + 40, pos);

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
		
		if(pos > 1)
		{
			Transaction *t1, *t2;
			finalize_data ndata;

			web::get_edge_nodes(t1, t2);
			std::string t1_hash = t1->get_hash();
			std::string t2_hash = t2->get_hash();

			memcpy(ndata.verify,      t1->txid.c_str(), 32);
			memcpy(ndata.verify + 32, t1_hash.c_str(),  32);
			memcpy(ndata.verify + 64, t2->txid.c_str(), 32);
			memcpy(ndata.verify + 96, t2_hash.c_str(),  32);

			ndata.pos = web::get_next_tx_pos();
			data.store(ndata);

			delete t1;
			delete t2;
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
			if(us_now - us_inc >= 1000000 && pos > 1)
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

				ndata.pos = web::get_next_tx_pos();
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
		input.nextpos = -1;
		input.prevpos = -1;

		inputs.push_back(input);
	}
	
	finalized = true;
}

void Transaction::optimize()
{
	// find real positions of transactions
	if(verifies_pos[0] == -1 && verifies[0].length() == 64)
			verifies_pos[0] = web::get_transaction_pos(verifies[0].c_str());
	if(verifies_pos[1] == -1 && verifies[1].length() == 64)
			verifies_pos[1] = web::get_transaction_pos(verifies[1].c_str());
	if(confirms_pos[0] == -1 && !is_id_unset(confirms[0]))
			confirms_pos[0] = web::get_transaction_pos(confirms[0].c_str());
	if(confirms_pos[1] == -1 && !is_id_unset(confirms[1]))
			confirms_pos[1] = web::get_transaction_pos(confirms[1].c_str());
	if(confirms_pos[2] == -1 && !is_id_unset(confirms[2]))
			confirms_pos[2] = web::get_transaction_pos(confirms[2].c_str());

	// find real positions of prev and next
	for(Transaction::Input& in : inputs)
	{
		if(in.prevpos == -1 && !is_id_unset(in.prev))
				in.prevpos = web::get_transaction_pos(in.prev.c_str());
		if(in.nextpos == -1 && !is_id_unset(in.next))
				in.nextpos = web::get_transaction_pos(in.next.c_str());
	}	
}

std::string Transaction::get_txid()
{
	return txid;
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

	if(!is_id_unset(txid)) root["txid"] = to_hex(txid);
	if(!is_id_unset(txnoise)) root["txnoise"] = to_hex(txnoise);
	if(!is_id_unset(txid)) root["txhash"] = to_hex(get_hash());
	root["created"] = std::to_string(created);
	root["received"] = std::to_string(received);
	root["total"] = std::to_string(get_total());
	root["confirmed"] = is_confirmed();
	root["finalized"] = is_finalized();
	root["valid"] = error ? false : true;
	if(error) root["error"] = std::string(error);
	
	int at = 0;

	for(int i = 0; i < 2; i++)
	{
		if(!is_id_unset(verifies[i].substr(0, 32)))
		{
			root["verifies"][at] = to_hex(verifies[i]);
			at += 1;
		}
	}

	at = 0;

	for(int i = 0; i < 3; i++)
	{
		if(!is_id_unset(confirms[i]))
		{
			root["confirms"][at] = to_hex(confirms[i]);
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
			input_j["balance"] = std::to_string(input.balance);
			input_j["amount"] = std::to_string(input.amount);
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
			input_j["balance"] = std::to_string(input.balance);
			input_j["amount"] = std::to_string(input.amount);
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

std::string Transaction::to_string(int indent)
{
	const char* error = get_errors();
	
	std::string out = calc_indent(indent)+"Transaction (" +
			"\n"+calc_indent(indent+1)+"txid = " + (is_id_unset(txid) ? "unset" : to_hex(txid)) +
			"\n"+calc_indent(indent+1)+"txnoise = " + (is_id_unset(txnoise) ? "unset" : to_hex(txnoise)) +
			"\n"+calc_indent(indent+1)+"txhash = " + (is_id_unset(txid) ? "unset" : to_hex(get_hash())) +
			"\n"+calc_indent(indent+1)+"created = " + std::to_string(created) + 
			"\n"+calc_indent(indent+1)+"received = " + std::to_string(received) +
			"\n"+calc_indent(indent+1)+"total = " + display_coins(get_total()) +
			"\n"+calc_indent(indent+1)+"confirmed = " + (is_confirmed() ? "1" : "0") +
			"\n"+calc_indent(indent+1)+"finalized = " + (is_finalized() ? "1" : "0") +
			"\n"+calc_indent(indent+1)+"valid = " + (error ? ("0\n"+calc_indent(indent+1)+"error = " + std::string(error)) : "1") +
			"\n"+calc_indent(indent+1)+"verifies = [";

	for(int i = 0; i < 2; i++)
	{
		if(!is_id_unset(verifies[i].substr(0, 32)))
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
					"\n"+calc_indent(indent+3)+"amount = " + display_coins(input.amount) +
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
					"\n"+calc_indent(indent+3)+"balance = " + display_coins(input.balance) +
					"\n"+calc_indent(indent+3)+"amount = " + display_coins(input.amount) +
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

bool Transaction::add_confirm(std::string id, uint64_t pos)
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
			confirms_pos[i] = pos;

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

