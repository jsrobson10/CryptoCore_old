
#pragma once

#include <fstream>
#include <string>

class Database
{
public:
	
	Database(std::string filename);
	Database(std::string filename, bool clear);
	~Database();
	void read(char* data, size_t len);
	void write(const char* data, size_t len);
	void begin(uint64_t offset);
	void end(uint64_t offset);
	void shift(int64_t amount);
	uint64_t get_pos();
	uint64_t get_len();
	void flush();
	void close();
	bool eof();

	uint64_t read_netul();
	uint32_t read_netui();
	uint16_t read_netus();
	double read_netd();
	float read_netf();

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

