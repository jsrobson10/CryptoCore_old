
#include "sig.hpp"
#include "web.hpp"
#include "address.hpp"
#include "transaction.hpp"
#include "helpers.hpp"
#include "database.hpp"

#include <openssl/rand.h>

#include <functional>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <list>

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

std::list<Transaction*> edge_nodes;

Database* transactions;
Database* chain;

};

using namespace web;

Transaction* web::get_transaction(std::string txid)
{
	return get_transaction(txid.c_str());
}

Transaction* web::get_transaction(uint64_t chpos)
{
	chain->begin(chpos * 16);

	uint128_t txpos = chain->read_netue();
	transactions->begin(txpos);

	size_t txlen = transactions->read_netui();
	char* txc = new char[txlen];

	transactions->read(txc, txlen);
	Transaction* tx = new Transaction(txc, txlen, nullptr, nullptr, txpos, true);
	
	delete[] txc;
	return tx;
}

Transaction* web::get_transaction(const char* txid)
{
	uint64_t txpos = get_transaction_pos(txid);

	if(txpos != -1)
	{
		return get_transaction(txpos);
	}

	else
	{
		return nullptr;
	}
}

uint64_t web::get_transaction_pos(const char* txid)
{
	uint128_t bpos = get_id_data(txid);
	uint64_t date_start = 0;

	uint128_t chpos = bpos * 16;
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
			return chpos / 16;
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
			return chpos / 16;
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
	chain->end(0);
	
	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(chain->get_pos() != 0)
	{
		chain->shift(-16);
		uint128_t txpos = chain->read_netue();

		chain->shift(-16);
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();

		// prevent buffer overflow
		if(txlen > 1048576)
		{
			continue;
		}

		transactions->read(txbuff, txlen);
		Transaction tx(txbuff, txlen, nullptr, nullptr, txpos, true);

		for(Transaction::Input& in : tx.inputs)
		{
			if(in.address == address)
			{
				delete[] txbuff;
				return new Transaction(tx);
			}
		}
	}

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

	chain->begin((uint128_t)begin * 16);

	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(found < limit && !chain->eof())
	{
		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();

		// prevent buffer overflow
		if(txlen > 1048576)
		{
			continue;
		}

		transactions->read(txbuff, txlen);
		Transaction tx(txbuff, txlen, nullptr, nullptr, txpos, true);

		for(Transaction::Output& out : tx.outputs)
		{
			if(out.address == find)
			{
				transactions_found.push_back(new Transaction(tx));
				found += 1;
				break;
			}
		}
	}

	delete[] txbuff;
	return found;
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

	uint128_t chpos = (uint128_t)begin * 16;
	uint128_t chlen = chain->get_len();

	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(chpos < chlen)
	{
		chain->begin(chpos);
		chpos += 16;

		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();

		// prevent buffer overflow
		if(txlen > 1048576)
		{
			continue;
		}

		transactions->read(txbuff, txlen);
		Transaction tx(txbuff, txlen, nullptr, nullptr, txpos, true);

		for(Transaction::Output& out : tx.outputs)
		{
			if(out.address == find)
			{
				if(!callback(tx, out))
				{
					delete[] txbuff;
					return found;
				}

				found += 1;

				break;
			}
		}
	}

	delete[] txbuff;
	return found;
}

void web::show_all()
{
	uint128_t chpos = 0;
	uint128_t chlen = chain->get_len();
	
	// 1 MB transaction buffer
	char* txbuff = new char[1048576];

	while(chpos < chlen)
	{
		chain->begin(chpos);
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
		Transaction tx(txbuff, txlen, nullptr, nullptr, txpos, true);

		std::cout << tx.to_string(0) << std::endl;
	}

	delete[] txbuff;
}

void web::add_transaction(Transaction* t)
{
	transactions->end(0);
	chain->end(0);
	
	uint128_t transactions_end_pos = transactions->get_pos();
	uint128_t tx_pos = chain->get_pos();

	t->set_pos(tx_pos / 16);
	t->finalize();
	t->optimize();

	size_t txlen = t->serialize_len();
	char* tx = new char[txlen + 4];
	
	t->serialize(tx + 4);

	std::string txid = t->get_txid();
	char pos_c[16];

	put_netui(tx, txlen);
	put_netue(pos_c, transactions_end_pos);

	chain->write(pos_c, 16);
	chain->flush();

	transactions->write(tx, txlen + 4);
	transactions->flush();

	delete[] tx;
}

void web::init()
{
	uint64_t now = get_micros();
	
	transactions = new Database("transactions.bin");
	chain = new Database("chain.bin");

	transactions->end(0);
	chain->end(0);

	uint128_t len_t = transactions->get_pos();
	uint128_t len_c = chain->get_pos();

	if(len_t == -1 || len_c == -1 || len_t < sizeof(BIN_TRANSACTIONS) || len_c < sizeof(BIN_CHAIN))
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

		return;
	}

	// find all edge nodes
	{
		// 1 MB transaction buffer
		char* txbuff = new char[1048576];

		uint128_t chlen = chain->get_len();
		uint128_t chpos = chlen;

		while(chpos > 0)
		{
			chpos -= 16;
			chain->begin(chpos);

			uint128_t txpos = chain->read_netue();
			transactions->begin(txpos);

			uint32_t txlen = transactions->read_netui();

			// prevent buffer overflow
			if(txlen > 1048576)
			{
				continue;
			}

			transactions->read(txbuff, txlen);
			Transaction tx(txbuff, txlen, nullptr, nullptr, txpos, true);

			if(tx.count_confirms() < 2)
			{
				edge_nodes.push_back(new Transaction(tx));
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
	
	// automatically remove old edge nodes
	if(edge_nodes.size() > 1024)
	{
		for(auto it = edge_nodes.begin(); it != edge_nodes.end(); it++)
		{
			Transaction* tx = *it;

			if(now > tx->received + 86400000000L && edge_nodes.size() > 1024)
			{
				edge_nodes.erase(it++);

				delete tx;
				continue;
			}
		}
	}

	// automatically remove confirmed nodes
	for(auto it = edge_nodes.begin(); it != edge_nodes.end(); it++)
	{
		Transaction* tx = *it;

		if(tx->count_confirms() > 2)
		{
			edge_nodes.erase(it++);

			delete tx;
			continue;
		}
	}
}

void web::get_edge_nodes(Transaction*& tx1, Transaction*& tx2)
{
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

	tx1 = *it;

	for(;i < item2;)
	{
		it++;
		i++;
	}

	tx2 = *it;
}

void web::cleanup()
{
	web::transactions->close();
	web::chain->close();

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

	std::string prikey1 = sig::generate();
	std::string prikey2 = sig::generate();

	std::string address1 = address::fromprikey(prikey1);
	std::string address2 = address::fromprikey(prikey2);

	std::list<std::string> sources;

	t1.set_pos(0);
	t2.set_pos(1);

	t1.add_input(prikey1, 0, "", sources);
	t1.add_output(address2, -1);
	t1.finalize();

	sources.push_back(t1.get_txid());
	
	t2.add_input(prikey2, 0, "", sources);
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

	std::cerr << "prikey: " << to_hex(prikey1) << std::endl;

	delete[] t_data;
}

