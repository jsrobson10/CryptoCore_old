
#include "block.hpp"
#include "helpers.hpp"
#include "ec.hpp"

#include <cstring>

#include <openssl/rand.h>
#include <openssl/sha.h>

/*
 *
 * Block format
 *
 * (created, 8) (txlen, 4) (blockid, 32) (blockhash_last, 32) ...[txlen] [Transaction] (siglen, 1) (sig, siglen)
 *
 */

Block::Block(std::string bh_last)
{
	char blockid_c[32];

	RAND_bytes((unsigned char*)blockid_c, 32);
	blockid = std::string(blockid_c, 32);
	blockhash_last = bh_last;

	received = get_micros();
	created = received;

	signed_status = false;
	valid = true;
}

Block::Block(const char** data, size_t* size)
{
	if(*size < 76)
	{
		valid = false;
		return;
	}
	
	created = get_netl(*data);
	received = get_micros();
	signed_status = true;
	valid = true;

	uint32_t tx_len = get_neti(*data + 8);
	char buff[32];

	memcpy(buff, *data + 12, 32);
	blockid = std::string(buff, 32);

	memcpy(buff, *data + 44, 32);
	blockhash_last = std::string(buff, 32);

	*data += 76;
	*size -= 76;

	for(int i = 0; i < tx_len; i++)
	{
		Transaction* t = new Transaction(data, size);

		if(!t->is_valid())
		{
			valid = false;
			return;
		}

		transactions.push_back(t);
	}

	if(*size == 0)
	{
		valid = false;
		return;
	}

	unsigned char sig_len = **(unsigned char**)data;
	char sig_c[SIG_LEN_MAX];

	if(sig_len > SIG_LEN_MAX || 1 + sig_len > *size)
	{
		valid = false;
		return;
	}

	memcpy(sig_c, *data + 1, sig_len);
	sig = std::string(sig_c, sig_len);

	*data += 1 + sig_len;
	*size -= 1 + sig_len;
}

Block::~Block()
{
	for(Transaction* t : transactions)
	{
		delete t;
	}
}

size_t Block::serialize_t_len()
{
	size_t len = 76;

	for(Transaction* t : transactions)
	{
		len += t->serialize_len();
	}

	return len;
}

char* Block::serialize_t(char* data)
{
	put_netl(data, created);
	put_neti(data + 8, transactions.size());
	memcpy(data + 12, blockid.c_str(), 32);
	memcpy(data + 44, blockhash_last.c_str(), 32);

	data += 76;

	for(Transaction* t : transactions)
	{
		data = t->serialize(data);
	}

	return data;
}

size_t Block::serialize_len()
{
	if(!signed_status)
	{
		return 0;
	}

	return serialize_t_len() + sig.length() + 1;
}

char* Block::serialize(char* data)
{
	data = serialize_t(data);

	*(unsigned char*)data = sig.length() & 255;

	memcpy(data + 1, sig.c_str(), sig.length());
		
	return data + sig.length() + 1;
}

void Block::add_transaction(Transaction& t)
{
	transactions.push_back(new Transaction(t));
}

std::list<Transaction*>* Block::get_transactions()
{
	return &transactions;
}

void Block::sign(std::string prikey)
{
	if(signed_status || transactions.size() == 0 || ec::get_pubkey(prikey) != (*transactions.begin())->get_pubkey())
	{
		return;
	}
	
	std::string work = get_work();
	sig = ec::sign(prikey, work);

	signed_status = true;
}

bool Block::is_signed()
{
	return signed_status;
}

bool Block::is_valid()
{
	return (get_errors() == nullptr);
}

const char* Block::get_errors()
{
	if(!valid)
	{
		return "valid flag is unset";
	}

	if(!signed_status)
	{
		return "block is not signed";
	}

	return nullptr;
}

std::string Block::get_blockid()
{
	return blockid;
}

std::string Block::get_lastblockhash()
{
	return blockhash_last;
}

std::string Block::get_work()
{
	size_t block_len = serialize_t_len();
	char* block_c = new char[block_len];

	serialize_t(block_c);

	char checksum[32];

	SHA256((unsigned char*)block_c, block_len, (unsigned char*)checksum);

	delete[] block_c;

	return std::string(checksum, 32);
}

uint64_t Block::get_received()
{
	return received;
}

uint64_t Block::get_created()
{
	return created;
}

std::string Block::to_string(int indent)
{
	const char* error = get_errors();

	std::string str = calc_indent(indent)+"Block (" + 
			"\n"+calc_indent(indent+1)+"blockid = " + to_hex(blockid) +
			"\n"+calc_indent(indent+1)+"valid = " + (error ? ("0\n"+calc_indent(indent+1)+"error = " + std::string(error)) : "1") +
			"\n"+calc_indent(indent+1)+"signed = " + (is_signed() ? ("1\n"+calc_indent(indent+1)+"sig = " + to_hex(sig)) : "0") +
			"\n"+calc_indent(indent+1)+"work = " + to_hex(get_work()) +
			"\n"+calc_indent(indent+1)+"lastblockhash = " + to_hex(blockhash_last) +
			"\n"+calc_indent(indent+1)+"created = " + std::to_string(created) +
			"\n"+calc_indent(indent+1)+"received = " + std::to_string(received) +
			"\n"+calc_indent(indent+1)+"tx_count = " + std::to_string(transactions.size()) +
			"\n"+calc_indent(indent+1)+"transactions = [\n";

	for(Transaction* t : transactions)
	{
		str += t->to_string(indent + 2);
	}

	return str + calc_indent(indent+1)+"]"+calc_indent(indent+1)+"\n)"+calc_indent(indent)+"";
}

