
#include "sig.hpp"
#include "cpu.hpp"
#include "config.hpp"
#include "helpers.hpp"

#include "falcon/falcon1024avx2/api.h"
#include "falcon/falcon1024int/api.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <unordered_map>
#include <string>

#define SEED_BEGIN_CHAR 0x80

namespace sig
{
	struct sig_item
	{
		std::string prikey;
		uint64_t accessed;
	};

	std::unordered_map<std::string, sig_item> cache;
};

std::string sig::generate()
{
	uint8_t* prikey = new uint8_t[SIG_LEN_PRIKEY];
	uint8_t seed[64];

	RAND_bytes(seed, sizeof(seed));

	if(cpu::avx2)
	{
		SIG_FALCON1024_avx2_sign_keypair(prikey + 2305, prikey,
						seed, sizeof(seed));
	}

	else
	{
		SIG_FALCON1024_int_sign_keypair(prikey + 2305, prikey,
						seed, sizeof(seed));
	}

	std::string prikey_s((char*)prikey, SIG_LEN_PRIKEY);

	delete[] prikey;
	return prikey_s;
}

std::string sig::seed_generate()
{
	uint8_t seed[65];

	seed[0] = SEED_BEGIN_CHAR;

	RAND_bytes(seed + 1, 32);
	SHA256(seed + 1, 32, seed + 33);

	return std::string((char*)seed, 40);
}

std::string sig::seed_generate(std::string data)
{
	uint8_t seed[65];

	seed[0] = SEED_BEGIN_CHAR;

	SHA256((uint8_t*)data.c_str(), data.length(), seed + 1);
	SHA256(seed + 1, 32, seed + 33);

	return std::string((char*)seed, 40);
}

bool sig::seed_verify(std::string seed)
{
	if(seed.length() != 40 || (uint8_t)seed[0] != SEED_BEGIN_CHAR)
	{
		return false;
	}
		
	char checksum[32];

	SHA256((uint8_t*)seed.c_str() + 1, 32, (uint8_t*)checksum);

	return (checksum[0] == seed[33] &&
			checksum[1] == seed[34] &&
			checksum[2] == seed[35] &&
			checksum[3] == seed[36] &&
			checksum[4] == seed[37] &&
			checksum[5] == seed[38] &&
			checksum[6] == seed[39]);
}

std::string sig::generate(std::string seed)
{
	// try to get the prikey from cache first
	sig_item& si = cache[seed];
	si.accessed = get_micros();
	
	if(si.prikey.length() > 0)
	{
		return si.prikey;
	}
	
	// calculate the prikey from the seed
	uint8_t* prikey = new uint8_t[SIG_LEN_PRIKEY];
	uint8_t seed_c[32];

	SHA256((uint8_t*)seed.c_str(), seed.length(), seed_c);

	if(cpu::avx2)
	{
		SIG_FALCON1024_avx2_sign_keypair(prikey + 2305, prikey,
						seed_c, sizeof(seed_c));
	}

	else
	{
		SIG_FALCON1024_int_sign_keypair(prikey + 2305, prikey,
						seed_c, sizeof(seed_c));
	}

	std::string prikey_s((char*)prikey, SIG_LEN_PRIKEY);

	// add the seed and prikey to cache
	si.prikey = std::string((char*)prikey, SIG_LEN_PRIKEY);
	si.accessed = get_micros();

	delete[] prikey;
	return prikey_s;
}

void sig::update()
{
	// remove the oldest item from cache
	if(cache.size() > config::cache_size)
	{
		std::unordered_map<std::string, sig_item>::iterator worst;
		uint64_t worst_time = -1;

		for(auto it = cache.begin(); it != cache.end(); it++)
		{
			uint64_t accessed = it->second.accessed;

			if(accessed < worst_time)
			{
				worst_time = accessed;
				worst = it;
			}
		}

		if(worst_time != -1)
		{
			cache.erase(worst);
		}
	}
}

std::string sig::sign(std::string prikey, std::string message)
{
	uint8_t* sig = new uint8_t[SIG_LEN];
	unsigned long long siglen;

	if(cpu::avx2)
	{
		SIG_FALCON1024_avx2_sign_signature(sig, &siglen,
						(uint8_t*)message.c_str(), message.length(),
						(uint8_t*)prikey.c_str());
	}

	else
	{
		SIG_FALCON1024_int_sign_signature(sig, &siglen, 
						(uint8_t*)message.c_str(), message.length(),
						(uint8_t*)prikey.c_str());
	}

	std::string sig_s((char*)sig, siglen);

	delete[] sig;
	return sig_s;
}

bool sig::verify(std::string pubkey, std::string message, std::string sig)
{
	if(cpu::avx2)
	{
		return (SIG_FALCON1024_avx2_sign_verify(
								(uint8_t*)message.c_str(), message.length(),
								(uint8_t*)sig.c_str(), sig.length(),
								(uint8_t*)pubkey.c_str()) == 0);
	}

	else
	{
		return (SIG_FALCON1024_int_sign_verify(
								(uint8_t*)message.c_str(), message.length(),
								(uint8_t*)sig.c_str(), sig.length(),
								(uint8_t*)pubkey.c_str()) == 0);
	}
}

std::string sig::getpubkey(std::string prikey)
{
	return std::string(prikey.c_str() + 2305, SIG_LEN_PUBKEY);
}

