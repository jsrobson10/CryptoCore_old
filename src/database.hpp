
#pragma once

#include <fstream>
#include <string>

typedef __uint128_t uint128_t;
typedef __int128_t int128_t;

class Database
{
public:
	
	Database(std::string filename);
	~Database();
	void read(char* data, size_t len);
	void write(const char* data, size_t len);
	void begin(uint128_t offset);
	void end(uint128_t offset);
	void shift(int128_t amount);
	uint128_t get_pos();
	void flush();
	void close();
	bool eof();

	uint128_t read_netue();
	uint64_t read_netul();
	uint32_t read_netui();
	uint16_t read_netus();
	double read_netd();
	float read_netf();

	void write_netue(uint128_t v);
	void write_netul(uint64_t v);
	void write_netui(uint32_t v);
	void write_netus(uint16_t v);
	void write_netd(double v);
	void write_netf(float v);

private:
	
	std::fstream* file;
	uint64_t pos;
	uint64_t len;
};

