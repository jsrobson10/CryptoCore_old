
#include <fstream>
#include <exception>

#include "database.hpp"
#include "helpers.hpp"

Database::Database(std::string filename, bool clear)
{
	if(clear)
	{
		std::ofstream f(filename, std::ios::binary | std::ios::trunc);
		f.close();
	}
		
	file = new std::fstream(filename, std::ios::binary | std::ios::in | std::ios::out | std::ios::ate);
	size_t filelen = file->tellg();

	len = filelen;
	pos = filelen;
}

Database::Database(std::string filename) : Database (filename, false)
{
	
}

Database::~Database()
{
	delete file;
}

void Database::read(char* data, size_t size)
{
	file->read(data, size);
	pos += size;

	if(pos > len)
	{
		throw std::overflow_error("database read overflow");
	}
}

void Database::write(const char* data, size_t size)
{
	if(data != nullptr)
	{
		file->write(data, size);
	}

	pos += size;

	if(pos > len)
	{
		len = pos;
	}
}

void Database::begin(uint64_t offset)
{
	pos = offset;
	file->seekg(pos, std::ios::beg);

	if(pos > len)
	{
		throw std::overflow_error("database position overflow");
	}
}

void Database::end(uint64_t offset)
{
	if(offset > len)
	{
		throw std::overflow_error("database position overflow");
	}
	
	else
	{
		pos = len - offset;
		file->seekg(pos, std::ios::beg);
	}
}

void Database::shift(int64_t offset)
{
	if(pos + offset > len || pos < -offset)
	{
		throw std::overflow_error("database position overflow");
	}
	
	else
	{
		pos += offset;
		file->seekg(pos, std::ios::beg);
	}
}

uint64_t Database::get_pos()
{
	if(pos == -1)
	{
		return -1;
	}
	
	return pos;
}

uint64_t Database::get_len()
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

