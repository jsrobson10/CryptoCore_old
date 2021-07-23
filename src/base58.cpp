
#include "base58.hpp"

#include <vector>

#include <gmp.h>

std::string base58::encode(const char* data, size_t len)
{
	const char MAP[] = {
			'1','2','3','4','5','6','7','8',
			'9','A','B','C','D','E','F','G',
			'H','J','K','L','M','N','P','Q',
			'R','S','T','U','V','W','X','Y',
			'Z','a','b','c','d','e','f','g',
			'h','i','j','k','m','n','o','p',
			'q','r','s','t','u','v','w','x',
			'y','z'};

	mpz_t data_n;
	
	mpz_init(data_n);
	mpz_set_ui(data_n, 0);

	for(int i = 0; i < len; i++)
	{
		mpz_mul_ui(data_n, data_n, 256);
		mpz_add_ui(data_n, data_n, ((const unsigned char*)data)[i]);
	}

	char* bytes = new char[len * 2];
	char* end = bytes + len * 2 - 1;
	int end_s = 1;

	mpz_t r;
	mpz_init(r);

	while(mpz_cmp_ui(data_n, 0) != 0)
	{
		mpz_tdiv_qr_ui(data_n, r, data_n, 58);

		*end = MAP[mpz_get_ui(r)];
		end_s += 1;
		end -= 1;
	}

	std::string out(end, end_s);

	delete[] bytes;

	mpz_clear(data_n);
	mpz_clear(r);

	return out;
}

std::string base58::decode(const char* data, size_t len)
{
	return "";
}
