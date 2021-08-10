
#include "sig.hpp"
#include "web.hpp"
#include "address.hpp"
#include "transaction.hpp"
#include "helpers.hpp"
#include "database.hpp"

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

std::list<Transaction*> cache_nodes;
std::list<Transaction*> edge_nodes;

Database* transactions;
Database* chain;

};

using namespace web;

Transaction* web::get_transaction(std::string txid)
{
	return get_transaction(txid.c_str());
}

Transaction* web::get_transaction(uint128_t pos)
{
	transactions->begin(pos);

	size_t txlen = transactions->read_netui();
	char* txc = new char[txlen];

	transactions->read(txc, txlen);
	Transaction* tx = new Transaction(txc, txlen, nullptr, nullptr);
	
	delete[] txc;
	return tx;
}

Transaction* web::get_transaction(const char* txid)
{
	uint128_t bpos = get_id_data(txid);

	chain->begin(bpos * 16);

	uint64_t date_start = 0;

	// search forwards
	while(!chain->eof())
	{
		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();
		uint64_t txdate = transactions->read_netul();
		char tx_txid[32];

		transactions->read(tx_txid, 32);

		if(bytes_are_equal(tx_txid, txid, 32))
		{
			return web::get_transaction(txpos);
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
		return nullptr;
	}

	chain->begin(bpos * 16 - 16);

	// search backwards
	while(!chain->eof())
	{
		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();
		uint64_t txdate = transactions->read_netul();
		char tx_txid[32];

		transactions->read(tx_txid, 32);

		if(bytes_are_equal(tx_txid, txid, 32))
		{
			return web::get_transaction(txpos);
		}

		// outside the scope of 1 minute
		if(txdate < date_start - 60000000)
		{
			break;
		}

		// cannot go back, at the start
		if(chain->get_pos() < 32)
		{
			return nullptr;
		}

		chain->shift(-32);
	}

	return nullptr;
}

bool web::find_transactions(std::list<Transaction*>& transactions, std::string after, int limit)
{
	uint64_t begin = 0;

	if(after.length() == 32)
	{
		Transaction* t = web::get_transaction(after);

		begin = t->get_pos() + 1;

		delete t;
	}

	return false; //TODO
}

void web::show_all()
{
	chain->begin(0);

	while(!chain->eof())
	{
		uint128_t txpos = chain->read_netue();
		transactions->begin(txpos);

		uint32_t txlen = transactions->read_netui();
		char* txc = new char[txlen];

		transactions->read(txc, txlen);
		Transaction tx(txc, txlen, nullptr, nullptr);
		delete[] txc;

		std::cout << tx.to_string(0) << std::endl;
	}
}

void web::add_transaction(Transaction* t)
{
	transactions->end(0);
	chain->end(0);
	
	uint128_t transactions_end_pos = transactions->get_pos();
	uint128_t tx_pos = chain->get_pos();

	t->set_pos(tx_pos / 16);
	t->finalize();

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
}

void web::init()
{
	transactions = new Database("transactions.bin");
	chain = new Database("chain.bin");

	transactions->end(0);
	chain->end(0);

	uint128_t len_t = transactions->get_pos();
	uint128_t len_c = chain->get_pos();

	if(len_t == -1 || len_c == -1 || len_t < sizeof(BIN_TRANSACTIONS) || len_c < sizeof(BIN_CHAIN))
	{
		std::cerr << "Initializing the web\n";

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
	
	t2.add_input(prikey2, 0, t1.get_txid(), sources);
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

	std::cerr << t1.to_string(0) << t2.to_string(0) << std::endl;
	std::cerr << "prikey: " << to_hex(prikey1) << std::endl;

	delete[] t_data;
}

