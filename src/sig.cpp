
#include "sig.hpp"

#include <openssl/sha.h>
#include <oqs/oqs.h>

std::string sig::generate()
{
	uint8_t* prikey = new uint8_t[SIG_LEN_PRIKEY];
	
	OQS_SIG_falcon_1024_keypair(prikey + 2305, prikey);

	std::string prikey_s((char*)prikey, SIG_LEN_PRIKEY);

	delete[] prikey;
	return prikey_s;
}

std::string sig::generate_seed()
{
	uint8_t seed[48];

	RAND_bytes(seed, sizeof(seed));

	return std::string(seed, sizeof(seed));
}

std::string sig::generate(std::string seed)
{
	uint8_t* prikey = new uint8_t[SIG_LEN_PRIKEY];
	
	OQS_SIG_falcon_1024_keypair_seed(prikey + 2305, prikey, seed.c_str(), seed.length());

	std::string prikey_s((char*)prikey, SIG_LEN_PRIKEY);

	delete[] prikey;
	return prikey_s;
}

std::string sig::sign(std::string prikey, std::string message)
{
	uint8_t* sig = new uint8_t[SIG_LEN];
	size_t siglen;

	OQS_SIG_falcon_1024_sign(sig, &siglen, (uint8_t*)message.c_str(), message.length(), (uint8_t*)prikey.c_str());

	std::string sig_s((char*)sig, siglen);

	delete[] sig;
	return sig_s;
}

bool sig::verify(std::string pubkey, std::string message, std::string sig)
{
	return (OQS_SIG_falcon_1024_verify((uint8_t*)message.c_str(), message.length(), (uint8_t*)sig.c_str(), sig.length(), (uint8_t*)pubkey.c_str()) == OQS_SUCCESS);
}

std::string sig::getpubkey(std::string prikey)
{
	return std::string(prikey.c_str() + 2305, SIG_LEN_PUBKEY);
}

