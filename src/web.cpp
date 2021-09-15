
#include "sig.hpp"
#include "web.hpp"
#include "address.hpp"
#include "transaction.hpp"
#include "helpers.hpp"
#include "database.hpp"
#include "hashmap.hpp"
#include "wallet.hpp"

#include <openssl/rand.h>

#include <functional>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <list>
#include <mutex>

#define CACHE_MAX 1024

/*
 *
 * Chain format
 *
 * [pos, 16]
 * ...
 *
 * Transaction web format
 *
 * [txlen, 4]
 * [Transaction, txlen]
 * ...
 *
 */

namespace web
{

#include "web-constants.hpp"

	std::unordered_map<std::string, Transaction*> edge_nodes;

	Hashmap* transactions;
	Database* chain;

	std::mutex mtx;

};

using namespace web;

Transaction* web::get_transaction(const char* txid)
{
	mtx.lock();

	uint64_t txpos = transactions->get(txid);

	if(txpos == -1)
	{
		return nullptr;
	}

	uint16_t txlen = transactions->read_netus();
	char* txc = new char[txlen];

	transactions->read(txc, txlen);

	mtx.unlock();

	Transaction* tx = new Transaction(txc, txlen, true);
	tx->pos = txpos;

	delete[] txc;
	return tx;
}

Transaction* web::get_transaction(std::string txid)
{
	if(txid.length() != 32)
	{
		return nullptr;
	}

	return get_transaction(txid.c_str());
}

void web::update_transaction(Transaction& tx)
{
	mtx.lock();
	
	// check if edge nodes needs updating
	
	auto edge_nodes_it = edge_nodes.find(tx.txid);

	if(edge_nodes_it != edge_nodes.end())
	{
		delete edge_nodes_it->second;

		edge_nodes_it->second = new Transaction(tx);
	}

	auto tx_it = edge_nodes.find(tx.txid);
	
	if(tx_it != nullptr)
	{
		delete tx_it->second;

		tx_it->second = new Transaction(tx);
	}

	// update the filesystem
	
	uint64_t txpos = transactions->get(tx.txid.c_str());

	if(txpos == -1)
	{
		return;
	}

	uint16_t txlen = tx.serialize_len();

	if(txlen != transactions->read_netus())
	{
		return;
	}

	char* txc = new char[txlen];
	
	tx.serialize(txc);
	transactions->write(txc, txlen);

	mtx.unlock();

	delete[] txc;
}

void web::add_transaction(Transaction& t)
{
	// prepare this transaction to be stored
	t.finalize();

	size_t txlen = t.serialize_len();
	char* tx = new char[txlen];
	
	t.serialize(tx);

	mtx.lock();

	uint64_t txpos = transactions->create(t.txid.c_str(), txlen);
	uint64_t chpos = chain->get_len();

	if(txpos == -1)
	{
		throw std::runtime_error("Transaction already exists");
	}

	// write the new transaction to the web
	chain->begin(chpos);
	chain->write_netul(txpos);
	chain->flush();

	transactions->write_netui(txlen);
	transactions->write(tx, txlen);
	transactions->flush();
	
	edge_nodes[t.txid] = new Transaction(t);
	
	mtx.unlock();

	// update previous transactions to point to this one

	// confirms
	for(int i = 0; i < 2; i++)
	{
		Transaction* tx_conf = web::get_transaction(t.verifies[i]);

		if(tx_conf != nullptr)
		{
			tx_conf->add_confirm(t.txid);
			web::update_transaction(*tx_conf);

			delete tx_conf;
		}
	}

	// inputs
	for(Transaction::Input& in : t.inputs)
	{
		Transaction* tx_prev = web::get_transaction(in.prev);

		if(tx_prev != nullptr)
		{
			for(Transaction::Input& in_prev : tx_prev->inputs)
			{
				if(in_prev.address == in.address)
				{
					in_prev.next = t.txid;

					break;
				}
			}

			web::update_transaction(*tx_prev);

			delete tx_prev;
		}

		break;
	}

	// TODO sources
	
	wallet::add_transaction(t);

	delete[] tx;
}

void web::show_all()
{
	mtx.lock();

	uint64_t chpos = 0;
	uint64_t chlen = chain->get_len() / 8;
	
	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(chpos < chlen)
	{
		chain->begin(chpos * 8);
		uint64_t txpos = chain->read_netul();
		transactions->begin(txpos);
		chpos += 1;

		uint32_t txlen = transactions->read_netui();
		
		// prevent buffer overflow
		if(txlen > 1048576)
		{
			continue;
		}
		
		transactions->read(txbuff, txlen);
		
		mtx.unlock();

		Transaction tx(txbuff, txlen, true);
		tx.pos = txpos;

		std::cout << tx.to_json() << std::endl;

		mtx.lock();
	}

	mtx.unlock();

	delete[] txbuff;
}

static void init_new()
{
	std::cout << "Initializing the web\n";

	transactions->close();
	chain->close();

	delete transactions;
	delete chain;

	transactions = new Hashmap("transactions.bin", true);
	chain = new Database("chain.bin", true);

	transactions->begin(0);
	chain->begin(0);

	transactions->write((const char*)BIN_TRANSACTIONS, sizeof(BIN_TRANSACTIONS));
	chain->write((const char*)BIN_CHAIN, sizeof(BIN_CHAIN));
}

void web::init()
{
	uint64_t now = get_micros();
	
	transactions = new Hashmap("transactions.bin");
	chain = new Database("chain.bin");

	uint64_t len_t = transactions->get_len();
	uint64_t len_c = chain->get_len();

	if(len_t == -1 || len_c == -1 || len_t < sizeof(BIN_TRANSACTIONS) || len_c < sizeof(BIN_CHAIN))
	{
		init_new();

		len_t = transactions->get_len();
		len_c = chain->get_len();
	}

	{
		// check if the web is correct and is consistent
		// with what is already in memory
		static uint8_t ch_check[sizeof(BIN_CHAIN)];
		//static uint8_t txs_check[204]; // TODO better transaction checking

		//transactions->begin(0);
		//transactions->read((char*)txs_check, sizeof(txs_check));

		chain->begin(0);
		chain->read((char*)ch_check, sizeof(ch_check));

		// is the first part of the transaction web correct
		/*for(int i = 0; i < sizeof(txs_check); i++)
		{
			if(txs_check[i] != BIN_TRANSACTIONS[i])
			{
				init_new();

				return;
			}
		}*/

		// is the first part of the chain correct
		for(int i = 0; i < sizeof(ch_check); i++)
		{
			if(ch_check[i] != BIN_CHAIN[i])
			{
				init_new();

				return;
			}
		}
	}

	// find all edge nodes
	{
		// 1 MB transaction buffer
		char* txbuff = new char[1048576];

		uint64_t chlen = chain->get_len() / 8;
		uint64_t chpos = chlen;

		while(chpos > 0)
		{
			chpos -= 1;
			chain->begin(chpos * 8);

			uint64_t txpos = chain->read_netul();

			transactions->begin(txpos);

			uint32_t txlen = transactions->read_netui();

			// prevent buffer overflow
			if(txlen > 1048576)
			{
				continue;
			}

			transactions->read(txbuff, txlen);
			Transaction tx(txbuff, txlen, true);
			tx.pos = txpos;

			if(tx.count_confirms() < 2)
			{
				edge_nodes[tx.txid] = new Transaction(tx);
			}

			// its safe to assume nodes older than a day shouldn't be cached if there's already enough edge nodes here
			if(now > tx.received + 86400000000L && edge_nodes.size() > 1024)
			{
				break;
			}
		}

		delete[] txbuff;
	}

	wallet::init();
}

void web::update()
{
	uint64_t now = get_micros();
	
	mtx.lock();

	// automatically remove old edge nodes
	if(edge_nodes.size() > 1024)
	{
		for(auto it = edge_nodes.begin(); it != edge_nodes.end();)
		{
			Transaction* tx = it->second;

			if(now > tx->received + 86400000000L && edge_nodes.size() > 1024)
			{
				edge_nodes.erase(it++);

				delete tx;
				continue;
			}

			else
			{
				it++;
			}
		}
	}

	// automatically remove confirmed nodes
	for(auto it = edge_nodes.begin(); it != edge_nodes.end();)
	{
		Transaction* tx = it->second;

		if(tx->count_confirms() > 2)
		{
			edge_nodes.erase(it++);

			delete tx;
			continue;
		}

		else
		{
			it++;
		}
	}

	mtx.unlock();
}

void web::get_edge_nodes(Transaction*& tx1, Transaction*& tx2)
{
	mtx.lock();
	
	uint64_t item1, item2, i;
	uint64_t edge_nodes_len = edge_nodes.size();
	
	// its ok to do this if this is the first 2 transactions
	if(edge_nodes_len < 2)
	{
		mtx.unlock();

		tx1 = nullptr;
		tx2 = nullptr;

		return;
	}

	RAND_bytes((uint8_t*)&item1, 8);
	RAND_bytes((uint8_t*)&item2, 8);

	// force item1 and item2 into a range
	item1 %= edge_nodes_len;
	item2 %= edge_nodes_len;

	// swap both, we want item1 first then item2
	if(item1 > item2)
	{
		i = item1;
		item1 = item2;
		item2 = i;
	}

	// cannot have duplicates
	if(item1 == item2)
	{
		if(item1 == 0)
		{
			item1 = 1;
		}

		else
		{
			item1 -= 1;
		}
	}

	// get item1 and item2
	auto it = edge_nodes.begin();

	for(i = 0; i < item1;)
	{
		it++;
		i++;
	}

	tx1 = new Transaction(*it->second);

	for(;i < item2;)
	{
		it++;
		i++;
	}

	tx2 = new Transaction(*it->second);

	mtx.unlock();
}

void web::cleanup()
{
	wallet::cleanup();
	web::transactions->close();
	web::chain->close();

	// clean up edge nodes
	for(auto& tx : edge_nodes)
	{
		delete tx.second;
	}

	delete web::transactions;
	delete web::chain;
}

void display_header(std::string name, const char* data, size_t len)
{
	std::cout << "\nconst uint8_t " << name << "[] = \n{\n    " << to_header(data, len) << "\n};\n";
}

void display_header(std::string name, std::string data)
{
	display_header(name, data.c_str(), data.length());
}

void web::generate_new()
{
	// clear and initialize the web
	transactions = new Hashmap("transactions.bin", true);
	chain = new Database("chain.bin", true);

	wallet::init_new();

	Transaction t1;
	Transaction t2;

	std::string seed1 = sig::seed_generate();
	std::string seed2 = sig::seed_generate();
	
	std::string prikey1 = sig::generate(seed1);
	std::string prikey2 = sig::generate(seed2);

	std::string address1 = address::fromprikey(prikey1);
	std::string address2 = address::fromprikey(prikey2);

	std::list<std::string> sources;

	t1.add_output(address1, -1);
	add_transaction(t1);

	sources.push_back(t1.txid);
	
	t2.add_input(prikey1, -1, 0, "", sources);
	t2.add_output(address2, -1);
	add_transaction(t2);
	
	wallet::cleanup();
	Hashmap addresses("addresses.bin");

	size_t t_datalen = transactions->get_len();
	char* t_data = new char[t_datalen];
	char t_data_chain[16];

	size_t addresses_len = addresses.get_len();
	char* addresses_data = new char[addresses_len];

	transactions->begin(0);
	transactions->read(t_data, t_datalen);

	chain->begin(0);
	chain->read(t_data_chain, sizeof(t_data_chain));

	addresses.begin(0);
	addresses.read(addresses_data, addresses_len);

	std::cout << "//auto-generated by web::generate_new()\n";
	display_header("BIN_TRANSACTIONS", t_data, t_datalen);
	display_header("BIN_CHAIN", t_data_chain, sizeof(t_data_chain));
	display_header("BIN_ADDRESSES", t_data_chain, sizeof(t_data_chain));

	std::cerr << "prikey: " << address::fromhash(seed2, ADDR_SECRET) << std::endl;

	delete[] t_data;
	delete[] addresses_data;
}

