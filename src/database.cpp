
#include <fstream>

#include "database.hpp"
#include "helpers.hpp"

Database::Database(std::string filename)
{
	file = new std::fstream(filename, std::ios::binary | std::ios::in | std::ios::out | std::ios::ate);

	size_t filelen = file->tellg();

	len = filelen;
	pos = filelen;
}

Database::~Database()
{
	delete file;
}

void Database::read(char* data, size_t len)
{
	file->read(data, len);
	pos += len;
}

void Database::write(const char* data, size_t len)
{
	file->write(data, len);
	pos += len;

	if(pos > len)
	{
		len = pos;
	}
}

void Database::begin(uint128_t offset)
{
	pos = (uint64_t)offset;
	file->seekg(pos, std::ios::beg);
}

void Database::end(uint128_t offset)
{
	if(offset > len)
	{
		pos = 0;
		file->seekg(0, std::ios::beg);
	}
	
	else
	{
		pos = len - (uint64_t)offset;
		file->seekg(pos, std::ios::beg);
	}
}

void Database::shift(int128_t offset)
{
	if(offset < 0 && -offset > pos)
	{
		pos = 0;
		file->seekg(0, std::ios::beg);
	}
	
	else
	{
		pos += (int64_t)offset;
		file->seekg(pos, std::ios::beg);
	}
}

uint128_t Database::get_pos()
{
	if(pos == -1)
	{
		return -1;
	}
	
	return pos;
}

uint128_t Database::get_len()
{
	return len;
}

void Database::flush()
{
	file->flush();
}

void Database::close()
{
	file->close();
}

bool Database::eof()
{
	return pos >= len;
}

uint128_t Database::read_netue()
{
	char data[16];
	read(data, 16);
	uint128_t v = get_netue(data);
	return v;
}

uint64_t Database::read_netul()
{
	char data[8];
	read(data, 8);
	return get_netul(data);
}

uint32_t Database::read_netui()
{
	char data[4];
	read(data, 4);
	return get_netui(data);
}

uint16_t Database::read_netus()
{
	char data[2];
	read(data, 2);
	return get_netus(data);
}

double Database::read_netd()
{
	char data[8];
	read(data, 8);
	return get_netd(data);
}

float Database::read_netf()
{
	char data[4];
	read(data, 4);
	return get_netf(data);
}

void Database::write_netue(uint128_t v)
{
	char data[16];
	put_netue(data, v);
	write(data, 16);
}

void Database::write_netul(uint64_t v)
{
	char data[8];
	put_netul(data, v);
	write(data, 8);
}

void Database::write_netui(uint32_t v)
{
	char data[4];
	put_netui(data, v);
	write(data, 4);
}

void Database::write_netus(uint16_t v)
{
	char data[2];
	put_netus(data, v);
	write(data, 2);
}

void Database::write_netd(double v)
{
	char data[8];
	put_netd(data, v);
	write(data, 8);
}

void Database::write_netf(float v)
{
	char data[4];
	put_netf(data, v);
	write(data, 4);
}

