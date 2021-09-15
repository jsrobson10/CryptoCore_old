
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

bool starts_with(std::string data, std::string value)
{
	if(value.length() > data.length())
	{
		return false;
	}

	auto data_at = data.begin();

	for(auto at = value.begin(); at != value.end(); at++)
	{
		if(*at != *data_at)
		{
			return false;
		}

		data_at++;
	}

	return true;
}

bool ends_with(std::string data, std::string value)
{
	if(value.length() > data.length())
	{
		return false;
	}

	auto data_at = data.end();

	for(auto at = value.end()-1; at != value.begin()-1; at--)
	{
		if(*at != *data_at)
		{
			return false;
		}

		data_at--;
	}

	return true;
}

std::string to_lower(std::string data)
{
	char* data_n = new char[data.length()];
	char* at_n = data_n;

	for(auto at = data.begin(); at != data.end(); at++)
	{
		char c = *at;

		if(c >= 'A' && c <= 'Z')
		{
			c += 32;
		}

		*at_n = c;
		at_n += 1;
	}

	std::string data_s(data_n, data.length());
	
	delete[] data_n;
	return data_s;
}

std::string to_upper(std::string data)
{
	char* data_n = new char[data.length()];
	char* at_n = data_n;

	for(auto at = data.begin(); at != data.end(); at++)
	{
		char c = *at;

		if(c >= 'a' && c <= 'z')
		{
			c -= 32;
		}

		*at_n = c;
		at_n += 1;
	}

	std::string data_s(data_n, data.length());
	
	delete[] data_n;
	return data_s;
}

std::string from_hex(std::string hex)
{
	const uint8_t HEX[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 
		0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0,
	};

	size_t datalen = hex.length() / 2;
	char* data = new char[datalen];

	for(int i = 0; i < datalen; i++)
	{
		data[i] = ((HEX[hex[i*2]] & 15) << 4) ^ (HEX[hex[i*2+1]] & 15);
	}

	std::string data_s(data, datalen);

	delete[] data;
	return data_s;
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

std::string to_header(const char* data, size_t len)
{
	const char HEX[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	char* out = new char[len * 6];
	size_t out_len = 0;
	
	char* at = out;

	for(int j = 0; j < len; j++)
	{
		at[0] = '0';
		at[1] = 'x';
		at[2] = HEX[(data[j] >> 4) & 15];
		at[3] = HEX[data[j] & 15];
		at[4] = ',';

		if(j % 16 == 15)
		{
			at[5] = '\n';
			at[6] = ' ';
			at[7] = ' ';
			at[8] = ' ';
			at[9] = ' ';
			out_len += 10;
			at += 10;
		}

		else
		{
			out_len += 5;
			at += 5;
		}
	}

	std::string out_str(out, out_len);

	delete[] out;
	return out_str;
}

std::string to_header(std::string data)
{
	return to_header(data.c_str(), data.length());
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
	const char END[] = {'k', 'm', 'g', 't', 'p', 'e'};
	
	int dp = 0;
	uint64_t coins_front = coins;

	while(coins_front > 10000)
	{
		coins_front /= 1000;
		dp += 1;
	}

	char number_s[12];
	char* end = number_s + 12;
	int len = 0;

	end[-1] = 'C';

	if(dp > 0)
	{
		end[-2] = END[dp - 1] & 255;
		
		end -= 2;
		len += 2;
	}

	else
	{
		end -= 1;
		len += 1;
	}

	int l = dp * 3;

	if(l > 4)
	{
		for(int i = 4; i < l; i++)
		{
			coins /= 10;
		}
			
		l = 4;
	}

	for(int i = 0; i < l; i++)
	{
		end -= 1;
		len += 1;

		*end = '0' + (coins % 10);
		coins /= 10;
	}
	
	if(dp > 0)
	{
		end -= 1;
		len += 1;

		*end = '.';
	}

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

bool bytes_are_equal(const char* a, const char* b, size_t len)
{
	const char* e = a + len;

	while(a != e)
	{
		if(*a != *b)
		{
			return false;
		}

		a += 1;
		b += 1;
	}

	return true;
}

std::string to_hex(std::string data)
{
	return to_hex(data.c_str(), data.length());
}

bool is_id_unset(std::string id)
{
	if(id.length() != 32)
	{
		return true;
	}

	for(int i = 0; i < 32; i++)
	{
		if(id[i] != '\0')
		{
			return false;
		}
	}

	return true;
}

void memcpy_if(char* dst, const char* src, char c, size_t len, bool cond)
{
	if(cond)
	{
		memcpy(dst, src, len);
	}

	else
	{
		memset(dst, c, len);
	}
}

void put_netul(char* data, uint64_t num)
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

void put_netui(char* data, uint32_t num)
{
	data[0] = (num >> 24) & 255;
	data[1] = (num >> 16) & 255;
	data[2] = (num >> 8) & 255;
	data[3] = num & 255;
}

void put_netus(char* data, uint16_t num)
{
	data[0] = (num >> 8) & 255;
	data[1] = num & 255;
}

void put_netf(char* data, float num)
{
	uint32_t num_int = *(uint32_t*)&num;

	put_netui(data, num_int);
}

void put_netd(char* data, double num)
{
	uint64_t num_int = *(uint64_t*)&num;

	put_netul(data, num_int);
}

uint64_t get_netul(const char* data)
{
	return (((uint64_t)data[0] & 255) << 56) ^
			(((uint64_t)data[1] & 255) << 48) ^
			(((uint64_t)data[2] & 255) << 40) ^
			(((uint64_t)data[3] & 255) << 32) ^
			(((uint64_t)data[4] & 255) << 24) ^
			(((uint64_t)data[5] & 255) << 16) ^ 
			(((uint64_t)data[6] & 255) << 8) ^ 
			((uint64_t)data[7] & 255);
}

uint32_t get_netui(const char* data)
{
	return (((uint32_t)data[0] & 255) << 24) ^ 
			(((uint32_t)data[1] & 255) << 16) ^ 
			(((uint32_t)data[2] & 255) << 8) ^ 
			((uint32_t)data[3] & 255);
}

uint16_t get_netus(const char* data)
{
	return (((uint16_t)data[0] & 255) << 8) ^ 
			((uint16_t)data[1] & 255);
}

float get_netf(const char* data)
{
	uint32_t num = get_netui(data);

	return *(float*)&num;
}

double get_netd(const char* data)
{
	uint64_t num = get_netul(data);

	return *(double*)&num;
}

