
#pragma once

#include <string>

unsigned long get_micros();

std::string from_hex(std::string hex);
std::string to_header(const char* data, size_t len);
std::string to_header(std::string data);
std::string to_hex(const char* data, size_t len);
std::string to_hex(std::string data);
std::string display_coins(uint64_t coins);
std::string display_unsigned_e(__uint128_t v);
std::string calc_indent(int amount);
std::string to_lower(std::string data);
std::string to_upper(std::string data);

bool starts_with(std::string data, std::string value);
bool ends_with(std::string data, std::string value);

void memcpy_if(char* dst, const char* src, char c, size_t len, bool cond);
bool bytes_are_equal(const char* a, const char* b, size_t len);
bool is_id_unset(std::string id);

uint64_t get_id_data(const char* id);
void set_id_data(char* id, uint64_t data);

void put_netue(char* data, __uint128_t num);
void put_netul(char* data, uint64_t num);
void put_netui(char* data, uint32_t num);
void put_netus(char* data, uint16_t num);
void put_netf(char* data, float num);
void put_netd(char* data, double num);

__uint128_t get_netue(const char* data);
uint64_t get_netul(const char* data);
uint32_t get_netui(const char* data);
uint16_t get_netus(const char* data);
float get_netf(const char* data);
double get_netd(const char* data);

