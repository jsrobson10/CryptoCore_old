
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
	memcpy(data, (char*)&num, 4);
}

void put_netd(char* data, double num)
{
	memcpy(data, (char*)&num, 8);
}

uint64_t get_netl(char* data)
{
	return (((uint64_t)data[0] & 255) << 56) ^ (((uint64_t)data[1] & 255) << 48) ^ (((uint64_t)data[2] & 255) << 40) ^ (((uint64_t)data[3] & 255) << 32) ^
			(((uint64_t)data[4] & 255) << 24) ^ (((uint64_t)data[5] & 255) << 16) ^ (((uint64_t)data[6] & 255) << 8) ^ ((uint64_t)data[7] & 255);
}

uint32_t get_neti(char* data)
{
	return (((uint32_t)data[0] & 255) << 24) ^ (((uint32_t)data[1] & 255) << 16) ^ (((uint32_t)data[2] & 255) << 8) ^ ((uint32_t)data[3] & 255);
}

uint16_t get_nets(char* data)
{
	return (((uint16_t)data[0] & 255) << 8) ^ ((uint16_t)data[1] & 255);
}

float get_netf(char* data)
{
	float num;

	memcpy((char*)&num, data, 4);

	return num;
}

double get_netd(char* data)
{
	double num;

	memcpy((char*)&num, data, 8);

	return num;
}

