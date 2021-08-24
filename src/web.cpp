
#include "sig.hpp"
#include "web.hpp"
#include "address.hpp"
#include "transaction.hpp"
#include "helpers.hpp"
#include "database.hpp"
#include "base58.hpp"

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

	Database* transactions;
	Database* chain;

	std::mutex mtx;

};

using namespace web;

uint64_t web::get_next_tx_pos()
{
	mtx.lock();

	uint64_t txpos = chain->get_len() / 16;

	mtx.unlock();

	return txpos;
}

Transaction* web::get_transaction(uint64_t chpos)
{
	mtx.lock();

	// search edge nodes first
	for(auto& tx : edge_nodes)
	{
		if(tx.second->pos == chpos)
		{
			Transaction* t = new Transaction(*tx.second);

			mtx.unlock();

			return t;
		}
	}
	
	// get from filesystem
	chain->begin(chpos * 16);

	uint128_t txpos = chain->read_netue();
	transactions->begin(txpos);

	size_t txlen = transactions->read_netui();
	char* txc = new char[txlen];

	transactions->read(txc, txlen);
	Transaction* tx = new Transaction(txc, txlen, nullptr, nullptr, txpos, true);

	mtx.unlock();

	delete[] txc;
	return tx;
}

Transaction* web::get_transaction(const char* txid)
{
	return get_transaction(std::string(txid, 32));
}

Transaction* web::get_transaction(std::string txid)
{
	// must be a proper transaction
	if(txid.length() != 32)
	{
		return nullptr;
	}

	mtx.lock();
	
	// search edge nodes first
	auto edge_nodes_it = edge_nodes.find(txid);

	if(edge_nodes_it != edge_nodes.end())
	{
		Transaction* t = new Transaction(*edge_nodes_it->second);

		mtx.unlock();

		return t;
	}

	mtx.unlock();

	// search from filesystem
	uint64_t txpos = get_transaction_pos(txid.c_str());

	if(txpos != -1)
	{
		return get_transaction(txpos);
	}

	else
	{
		return nullptr;
	}
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
	
	for(auto it = edge_nodes.begin(); it != edge_nodes.end(); it++)
	{
		if(it->second->pos == tx.pos)
		{
			delete it->second;

			it->second = new Transaction(tx);

			break;
		}
	}

	// update the filesystem
	size_t txlen = tx.serialize_len();
	char* txc = new char[txlen];

	tx.serialize(txc);
		
	chain->begin((uint128_t)tx.pos * 16);
	uint128_t txpos = chain->read_netue();

	transactions->begin(txpos + 4);
	transactions->write(txc, txlen);
	transactions->flush();

	mtx.unlock();

	delete[] txc;
}

uint64_t web::get_transaction_pos(const char* txid)
{
	mtx.lock();
	
	uint64_t bpos = get_id_data(txid);
	uint64_t date_start = 0;

	uint128_t chpos = (uint128_t)bpos * 16;
	uint128_t chlen = chain->get_len();

	// search forwards
	while(chpos < chlen)
	{
		chain->begin(chpos);
		chpos += 16;

		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();
		uint64_t txdate = transactions->read_netul();
		char tx_txid[32];

		transactions->shift(32);
		transactions->read(tx_txid, 32);

		if(bytes_are_equal(tx_txid, txid, 32))
		{
			mtx.unlock();

			return (chpos - 16) / 16;
		}

		if(date_start == 0)
		{
			date_start = txdate;
		}

		// outside scope of 1 minute
		else if(txdate > date_start + 60000000)
		{
			break;
		}
	}

	// cannot search back if already at the start
	if(bpos == 0)
	{
		mtx.unlock();

		return -1;
	}

	chpos = bpos * 16 - 16;

	// search backwards
	while(chpos > 0)
	{
		chain->begin(chpos);
		chpos -= 16;

		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();
		uint64_t txdate = transactions->read_netul();
		char tx_txid[32];

		transactions->shift(32);
		transactions->read(tx_txid, 32);

		if(bytes_are_equal(tx_txid, txid, 32))
		{
			mtx.unlock();

			return (chpos - 16) / 16;
		}

		// outside the scope of 1 minute
		if(txdate < date_start - 60000000)
		{
			break;
		}

		// cannot go back, at the start
		if(chain->get_pos() < 32)
		{
			break;
		}
	}

	mtx.unlock();

	return -1;
}

void web::get_address_info(std::string address, uint64_t& balance, Transaction*& latest, std::list<Transaction*>& sources_new, uint64_t sources_new_limit)
{
	latest = get_latest_from_address(address);
	balance = 0;

	// an address that hasn't been spent needs to be searched
	if(latest == nullptr)
	{
		find_outputs(address, "", [&balance, &sources_new, sources_new_limit](Transaction& tx, Transaction::Output& out)
		{
			balance += out.amount;

			if(sources_new.size() < sources_new_limit)
			{
				sources_new.push_back(new Transaction(tx));
			}

			return true;
		});

		return;
	}

	Transaction* prev = nullptr;
	std::list<std::string> sources;

	// find the sources of the latest spend and the previous transaction
	for(Transaction::Input& in : latest->inputs)
	{
		if(in.address == address)
		{
			if(in.prev != "")
			{
				prev = get_transaction(in.prev);
				break;
			}

			sources = in.sources;
			balance = in.balance;
		}
	}

	// address has only spent once
	if(prev == nullptr)
	{
		find_outputs(address, "", [&balance, &sources, &sources_new, sources_new_limit](Transaction& tx, Transaction::Output& out)
		{
			std::string txid = tx.get_txid();
			
			for(std::string& source : sources)
			{
				if(source == txid)
				{
					return true;
				}
			}
			
			if(sources_new.size() < sources_new_limit)
			{
				sources_new.push_back(new Transaction(tx));
			}

			balance += out.amount;

			return true;
		});
		
		return;
	}

	std::string source_best;
	uint64_t source_best_at = -1;

	// address spent more than once
	for(Transaction::Input& in : prev->inputs)
	{
		for(std::string& source : in.sources)
		{
			sources.push_back(source);

			uint64_t source_at = get_id_data(source.c_str());

			if(source_at > source_best_at)
			{
				source_best = source;
			}
		}
	}

	delete prev;

	find_outputs(address, source_best, [&balance, &sources, &sources_new, sources_new_limit](Transaction& tx, Transaction::Output& out)
	{
		std::string txid = tx.get_txid();
		
		for(std::string& source : sources)
		{
			if(source == txid)
			{
				return true;
			}
		}
		
		if(sources_new.size() < sources_new_limit)
		{
			sources_new.push_back(new Transaction(tx));
		}

		balance += out.amount;

		return true;
	});
}

Transaction* web::get_latest_from_address(std::string address)
{
	mtx.lock();
	
	uint64_t chpos = chain->get_len() / 16;
	
	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(chpos > 0)
	{
		chpos -= 1;
		chain->begin((uint128_t)chpos * 16);
		
		uint128_t txpos = chain->read_netue();

		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();

		// prevent buffer overflow
		if(txlen > 1048576)
		{
			continue;
		}

		transactions->read(txbuff, txlen);

		mtx.unlock();

		Transaction tx(txbuff, txlen, nullptr, nullptr, chpos, true);

		for(Transaction::Input& in : tx.inputs)
		{
			if(in.address == address)
			{
				delete[] txbuff;
				return new Transaction(tx);
			}
		}

		mtx.lock();
	}

	mtx.unlock();

	delete[] txbuff;
	return nullptr;
}

uint64_t web::find_outputs(std::list<Transaction*>& transactions_found, std::string find, std::string after, uint64_t limit)
{
	uint64_t begin = 0;
	uint64_t found = 0;

	// find the position to start searching at
	if(after.length() == 32)
	{
		Transaction* t = web::get_transaction(after);

		begin = t->get_pos() + 1;

		delete t;
	}

	mtx.lock();

	uint64_t chpos = begin;
	uint64_t chlen = chain->get_len() / 16;

	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(found < limit && chpos < chlen)
	{
		chain->begin((uint128_t)chpos * 16);
		chpos += 1;

		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();

		// prevent buffer overflow
		if(txlen > 1048576)
		{
			continue;
		}

		transactions->read(txbuff, txlen);

		mtx.unlock();

		Transaction tx(txbuff, txlen, nullptr, nullptr, chpos, true);

		for(Transaction::Output& out : tx.outputs)
		{
			if(out.address == find)
			{
				transactions_found.push_back(new Transaction(tx));
				found += 1;
				break;
			}
		}

		mtx.lock();
	}

	mtx.unlock();

	delete[] txbuff;
	return found;
}

void web::find_transactions(uint64_t& at, std::function<bool (Transaction& tx)> callback)
{
	mtx.lock();

	uint64_t chpos;
	uint64_t chlen = chain->get_len() / 16;
	
	if(at == -1)
	{
		chpos = chlen;
	}

	else
	{
		chpos = at;
	}

	// 1 MB transaction buffer
	char* txbuff = new char[1048576];
	
	while(chpos > 0)
	{
		// go to the right spot and read the transaction
		chpos -= 1;
		chain->begin((uint128_t)chpos * 16);

		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();

		// cannot be over 1 MB
		if(txlen > 1048576)
		{
			continue;
		}

		transactions->read(txbuff, txlen);

		mtx.unlock();
		
		Transaction tx(txbuff, txlen, nullptr, nullptr, chpos, true);
		callback(tx);

		mtx.lock();
	}

	mtx.unlock();
	at = chpos;

	delete[] txbuff;
}

uint64_t web::find_outputs(std::string find, std::string after, std::function<bool (Transaction& tx, Transaction::Output& out)> callback)
{
	uint64_t begin = 0;
	uint64_t found = 0;

	// find the position to start searching at
	if(after.length() == 32)
	{
		Transaction* t = web::get_transaction(after);

		begin = t->get_pos() + 1;

		delete t;
	}

	mtx.lock();

	uint64_t chpos = begin;
	uint64_t chlen = chain->get_len() / 16;

	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(chpos < chlen)
	{
		chain->begin((uint128_t)chpos * 16);
		chpos += 1;

		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();

		// prevent buffer overflow
		if(txlen > 1048576)
		{
			continue;
		}

		transactions->read(txbuff, txlen);

		mtx.unlock();

		Transaction tx(txbuff, txlen, nullptr, nullptr, chpos, true);

		for(Transaction::Output& out : tx.outputs)
		{
			if(out.address == find)
			{
				if(!callback(tx, out))
				{
					mtx.unlock();

					delete[] txbuff;
					return found;
				}

				found += 1;

				break;
			}
		}

		mtx.lock();
	}

	mtx.unlock();

	delete[] txbuff;
	return found;
}

void web::show_all()
{
	mtx.lock();

	uint64_t chpos = 0;
	uint64_t chlen = chain->get_len() / 16;
	
	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(chpos < chlen)
	{
		chain->begin((uint128_t)chpos * 16);
		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);
		chpos += 16;

		uint32_t txlen = transactions->read_netui();
		
		// prevent buffer overflow
		if(txlen > 1048576)
		{
			continue;
		}
		
		transactions->read(txbuff, txlen);
		
		mtx.unlock();

		Transaction tx(txbuff, txlen, nullptr, nullptr, chpos, true);

		std::cout << tx.to_string(0) << std::endl;

		mtx.lock();
	}

	mtx.unlock();

	delete[] txbuff;
}

void web::add_transaction(Transaction& t)
{
	// prepare this transaction to be stored
	t.set_pos(-1);
	t.finalize();
	t.optimize();

	size_t txlen = t.serialize_len();
	char* tx = new char[txlen];
	
	t.serialize(tx);

	mtx.lock();

	uint128_t txpos = transactions->get_len();
	uint128_t chpos = chain->get_len();

	// write the new transaction to the end of the web
	chain->begin(chpos);
	chain->write_netue(txpos);
	chain->flush();

	transactions->begin(txpos);
	transactions->write_netui(txlen);
	transactions->write(tx, txlen);
	transactions->flush();
	
	mtx.unlock();

	edge_nodes[t.txid] = new Transaction(t);

	// update previous transactions to point to this one

	// confirms
	for(int i = 0; i < 2; i++)
	{
		Transaction* tx_conf = web::get_transaction(t.verifies[i]);

		if(tx_conf != nullptr)
		{
			tx_conf->add_confirm(t.txid, t.pos);
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
					in_prev.nextpos = t.pos;

					break;
				}
			}

			web::update_transaction(*tx_prev);

			delete tx_prev;
		}

		break;
	}

	delete[] tx;
}

static void init_new()
{
	std::cout << "Initializing the web\n";

	transactions->close();
	chain->close();

	delete transactions;
	delete chain;

	std::ofstream transactions("transactions.bin", std::ios::binary);
	std::ofstream chain("chain.bin", std::ios::binary);

	transactions.write((const char*)BIN_TRANSACTIONS, sizeof(BIN_TRANSACTIONS));
	chain.write((const char*)BIN_CHAIN, sizeof(BIN_CHAIN));

	transactions.close();
	chain.close();

	web::init();
}

void web::init()
{
	uint64_t now = get_micros();
	
	transactions = new Database("transactions.bin");
	chain = new Database("chain.bin");

	uint128_t len_t = transactions->get_len();
	uint128_t len_c = chain->get_len();

	if(len_t == -1 || len_c == -1 || len_t < sizeof(BIN_TRANSACTIONS) || len_c < sizeof(BIN_CHAIN))
	{
		init_new();

		return;
	}

	{
		// check if the web is correct and is consistent
		// with what is already in memory
		static uint8_t txs_check[204];
		static uint8_t ch_check[32];

		transactions->begin(0);
		transactions->read((char*)txs_check, sizeof(txs_check));

		chain->begin(0);
		chain->read((char*)ch_check, sizeof(ch_check));

		// is the first part of the transaction web correct
		for(int i = 0; i < sizeof(txs_check); i++)
		{
			if(txs_check[i] != BIN_TRANSACTIONS[i])
			{
				init_new();

				return;
			}
		}

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

		uint64_t chlen = chain->get_len() / 16;
		uint64_t chpos = chlen;

		while(chpos > 0)
		{
			chpos -= 1;
			chain->begin((uint128_t)chpos * 16);

			uint128_t txpos = chain->read_netue();
			transactions->begin(txpos);

			uint32_t txlen = transactions->read_netui();

			// prevent buffer overflow
			if(txlen > 1048576)
			{
				continue;
			}

			transactions->read(txbuff, txlen);
			Transaction tx(txbuff, txlen, nullptr, nullptr, chpos, true);

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
	Transaction t1;
	Transaction t2;

	std::string seed1 = sig::seed_generate();
	std::string seed2 = sig::seed_generate();
	
	std::string prikey1 = sig::generate(seed1);
	std::string prikey2 = sig::generate(seed2);

	std::string address1 = address::fromprikey(prikey1);
	std::string address2 = address::fromprikey(prikey2);

	std::list<std::string> sources;

	t1.set_pos(0);
	t2.set_pos(1);

	t1.add_input(prikey1, -1, 0, "", sources);
	t1.add_output(address2, -1);
	t1.finalize();

	sources.push_back(t1.get_txid());
	
	t2.add_input(prikey2, -1, 0, "", sources);
	t2.add_output(address1, -1);
	t2.finalize();

	size_t t1_datalen = t1.serialize_len();
	size_t t2_datalen = t2.serialize_len();

	char* t_data = new char[t1_datalen + t2_datalen + 8];
	char t_data_chain[32];

	put_netue(t_data_chain, 0);
	put_netue(t_data_chain + 16, t1_datalen + 4);
	
	put_netui(t_data, t1_datalen);
	put_netui(t_data + t1_datalen + 4, t2_datalen);

	t1.serialize(t_data + 4);
	t2.serialize(t_data + 8 + t1_datalen);

	std::cout << "//auto-generated by web::generate_new()\n";
	display_header("BIN_TRANSACTIONS", t_data, t1_datalen + t2_datalen + 8);
	display_header("BIN_CHAIN", t_data_chain, 32);

	std::cerr << "prikey: " << base58::encode(seed1) << std::endl;

	delete[] t_data;
}

