
#include "helpers.hpp"

#include <sys/time.h>
#include <cstring>
#include <fstream>

unsigned long get_micros()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

std::string to_hex(const char* data, size_t len)
{
	const char HEX[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	
	const char* data_e = data + len;
	char* hex = new char[len * 2];
	char* hex_c = hex;

	while(data != data_e)
	{
		char v = *data;

		hex_c[0] = HEX[(v >> 4) & 15];
		hex_c[1] = HEX[v & 15];

		hex_c += 2;
		data += 1;
	}

	std::string hex_s(hex, len * 2);

	delete[] hex;

	return hex_s;
}

std::string calc_indent(int amount)
{
	char* indent = new char[2 * amount];

	for(int i = 0; i < 2 * amount; i++)
	{
		indent[i] = ' ';
	}

	std::string indent_s(indent, 2 * amount);

	delete[] indent;
	return indent_s;
}

std::string display_coins(uint64_t coins)
{
	char number_s[24];
	char* end = number_s + 18;
	int len = 6;

	number_s[23] = '\0';
	number_s[22] = '0' + (coins % 10);
	number_s[21] = '0' + ((coins / 10) % 10);
	number_s[20] = '0' + ((coins / 100) % 10);
	number_s[19] = '0' + ((coins / 1000) % 10);
	number_s[18] = '.';
	
	coins /= 10000;

	goto loop;

	while(coins != 0)
	{
loop:
		end -= 1;
		len += 1;

		*end = '0' + (coins % 10);
		coins /= 10;
	}

	return std::string(end, len);
}

std::string to_hex(std::string data)
{
	return to_hex(data.c_str(), data.length());
}

void put_netl(char* data, uint64_t num)
{
	data[0] = (num >> 56) & 255;
	data[1] = (num >> 48) & 255;
	data[2] = (num >> 40) & 255;
	data[3] = (num >> 32) & 255;
	data[4] = (num >> 24) & 255;
	data[5] = (num >> 16) & 255;
	data[6] = (num >> 8) & 255;
	data[7] = num & 255;
}

void put_neti(char* data, uint32_t num)
{
	data[0] = (num >> 24) & 255;
	data[1] = (num >> 16) & 255;
	data[2] = (num >> 8) & 255;
	data[3] = num & 255;
}

void put_nets(char* data, uint16_t num)
{
	data[0] = (num >> 8) & 255;
	data[1] = num & 255;
}

void put_netf(char* data, float num)
{
	uint32_t num_int = *(uint32_t*)&num;

	put_neti(data, num_int);
}

void put_netd(char* data, double num)
{
	uint64_t num_int = *(uint64_t*)&num;

	put_netl(data, num_int);
}

uint64_t get_netl(const char* data)
{
	return (((uint64_t)data[0] & 255) << 56) ^ (((uint64_t)data[1] & 255) << 48) ^ (((uint64_t)data[2] & 255) << 40) ^ (((uint64_t)data[3] & 255) << 32) ^
			(((uint64_t)data[4] & 255) << 24) ^ (((uint64_t)data[5] & 255) << 16) ^ (((uint64_t)data[6] & 255) << 8) ^ ((uint64_t)data[7] & 255);
}

uint32_t get_neti(const char* data)
{
	return (((uint32_t)data[0] & 255) << 24) ^ (((uint32_t)data[1] & 255) << 16) ^ (((uint32_t)data[2] & 255) << 8) ^ ((uint32_t)data[3] & 255);
}

uint16_t get_nets(const char* data)
{
	return (((uint16_t)data[0] & 255) << 8) ^ ((uint16_t)data[1] & 255);
}

float get_netf(const char* data)
{
	uint32_t num = get_neti(data);

	return *(float*)&num;
}

double get_netd(const char* data)
{
	uint64_t num = get_netl(data);

	return *(double*)&num;
}

