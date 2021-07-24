
#include "base58.hpp"

#include <vector>
#include <iostream>

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

	// convert all the data into a big int
	for(int i = 0; i < len; i++)
	{
		mpz_mul_ui(data_n, data_n, 256);
		mpz_add_ui(data_n, data_n, ((const unsigned char*)data)[i]);
	}

	char* bytes = new char[len * 2];
	char* end = bytes + len * 2;
	int end_s = 0;

	mpz_t r;
	mpz_init(r);

	// map all the big int data into base58
	while(mpz_cmp_ui(data_n, 0) != 0)
	{
		mpz_tdiv_qr_ui(data_n, r, data_n, 58);

		end_s += 1;
		end -= 1;

		*end = MAP[mpz_get_ui(r)];
	}

	std::string out(end, end_s);

	delete[] bytes;

	mpz_clear(data_n);
	mpz_clear(r);

	return out;
}

std::string base58::decode(const char* data, size_t len)
{
	const unsigned char MAP[] = {
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  0,  0,  0,  0,  0,  0, 
		0,  9,  10, 11, 12, 13, 14, 15, 16, 0,  17, 18, 19, 20, 21, 0, 
		22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0,  0,  0,  0,  0, 
		0,  33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 0, 44, 45, 46, 
		47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
	};

	mpz_t data_n;
	
	mpz_init(data_n);
	mpz_set_ui(data_n, 0);

	// convert all the base58 data mapped into a big int
	for(int i = 0; i < len; i++)
	{
		mpz_mul_ui(data_n, data_n, 58);
		mpz_add_ui(data_n, data_n, MAP[((const unsigned char*)data)[i]]);
	}

	char* bytes = new char[len];
	char* end = bytes + len;
	int end_s = 0;

	mpz_t r;
	mpz_init(r);

	// map all the big int data into binary
	while(mpz_cmp_ui(data_n, 0) != 0)
	{
		mpz_tdiv_qr_ui(data_n, r, data_n, 256);

		end_s += 1;
		end -= 1;

		*end = mpz_get_ui(r);
	}

	std::string out(end, end_s);

	delete[] bytes;

	mpz_clear(data_n);
	mpz_clear(r);
	
	return out;
}

std::string base58::encode(std::string data)
{
	return base58::encode(data.c_str(), data.length());
}

std::string base58::decode(std::string data)
{
	return base58::decode(data.c_str(), data.length());
}

