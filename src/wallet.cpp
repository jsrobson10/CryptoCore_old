
#include <mutex>
#include <string>
#include <list>

#include "wallet.hpp"
#include "hashmap.hpp"
#include "transaction.hpp"

namespace wallet
{

#include "web-constants.hpp"

	Hashmap* addresses;
	std::mutex mtx;

	static void add_to_address(Transaction& tx, std::string address);
};

void wallet::init_new()
{
	mtx.lock();
	
	addresses = new Hashmap("addresses.bin", true);

	addresses->begin(0);
	addresses->write((char*)BIN_ADDRESSES, sizeof(BIN_ADDRESSES));

	mtx.unlock();
}

void wallet::init()
{
	mtx.lock();
	
	addresses = new Hashmap("addresses.bin");

	if(addresses->get_len() == -1)
	{
		delete addresses;

		addresses = new Hashmap("addresses.bin", true);

		addresses->begin(0);
		addresses->write((char*)BIN_ADDRESSES, sizeof(BIN_ADDRESSES));
	}

	mtx.unlock();
}

void wallet::cleanup()
{
	mtx.lock();
	
	delete addresses;

	mtx.unlock();
}

static void wallet::add_to_address(Transaction& tx, std::string address)
{
	if(addresses->get(address.c_str()) == -1)
	{
		uint64_t pos = addresses->get_len();
			
		addresses->create(address.c_str(), 8);
		addresses->write_netul(pos);

		addresses->begin(pos);
		addresses->write(tx.txid.c_str(), 32);
		addresses->write_netul(-1);
	}

	else
	{
		uint64_t new_pos = addresses->get_len();
		uint64_t next_pos = addresses->read_netul();

		addresses->shift(-8);
		addresses->write_netul(new_pos);

		addresses->begin(new_pos);
		addresses->write(tx.txid.c_str(), 32);
		addresses->write_netul(next_pos);
	}
}

void wallet::add_transaction(Transaction& tx)
{
	mtx.lock();
	
	// record all inputs and outputs
	
	for(Transaction::Input& in : tx.inputs)
	{
		add_to_address(tx, in.address);
	}

	for(Transaction::Output& out : tx.outputs)
	{
		add_to_address(tx, out.address);
	}

	addresses->flush();
	mtx.unlock();
}

uint64_t wallet::get_latest(std::string address)
{
	mtx.lock();
	
	uint64_t pos = addresses->get(address.c_str());

	if(pos == -1)
	{
		mtx.unlock();

		return -1;
	}

	uint64_t first_pos = addresses->read_netul();

	mtx.unlock();

	return first_pos;
}

uint64_t wallet::get_prev(std::string& txid, uint64_t pos)
{
	mtx.lock();

	uint64_t prev_pos;
	char txid_c[32];

	addresses->begin(pos);
	prev_pos = addresses->read_netul();
	addresses->read(txid_c, 32);

	mtx.unlock();

	txid = std::string(txid_c, 32);

	return prev_pos;
}

