
#include "sig.hpp"
#include "cpu.hpp"
#include "config.hpp"
#include "helpers.hpp"

#include "falcon/falcon1024avx2/api.h"
#include "falcon/falcon1024int/api.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <mutex>
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
	std::mutex mtx;
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
	uint8_t seed[32];

	RAND_bytes(seed, 32);

	return std::string((char*)seed, 32);
}

std::string sig::seed_generate(std::string data)
{
	uint8_t seed[32];

	SHA256((uint8_t*)data.c_str(), data.length(), seed);

	return std::string((char*)seed, 32);
}

std::string sig::generate(std::string seed)
{
	mtx.lock();
	
	// try to get the prikey from cache first
	sig_item& si = cache[seed];
	si.accessed = get_micros();
	
	if(si.prikey.length() > 0)
	{
		mtx.unlock();

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

	mtx.unlock();

	delete[] prikey;
	return prikey_s;
}

void sig::update()
{
	// remove the oldest items from cache
	if(cache.size() > config::cache_size)
	{
		mtx.lock();
	
		std::unordered_map<std::string, sig_item>::iterator worst;
		__uint128_t mean_time_calc = 0;
		uint64_t mean_time = 0;

		// get the mean age of whats in cache
		for(auto it = cache.begin(); it != cache.end(); it++)
		{
			mean_time_calc += it->second.accessed;
		}

		mean_time = mean_time_calc / cache.size();

		// remove everything under the mean, approx half of whats here
		for(auto it = cache.begin(); it != cache.end();)
		{
			if(it->second.accessed <= mean_time)
			{
				cache.erase(it++);
			}

			else
			{
				it++;
			}
		}

		mtx.unlock();
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

