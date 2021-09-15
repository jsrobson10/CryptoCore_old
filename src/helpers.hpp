
#pragma once

#include <string>

unsigned long get_micros();

std::string from_hex(std::string hex);
std::string to_header(const char* data, size_t len);
std::string to_header(std::string data);
std::string to_hex(const char* data, size_t len);
std::string to_hex(std::string data);
std::string display_coins(uint64_t coins);
std::string calc_indent(int amount);
std::string to_lower(std::string data);
std::string to_upper(std::string data);

bool starts_with(std::string data, std::string value);
bool ends_with(std::string data, std::string value);

void memcpy_if(char* dst, const char* src, char c, size_t len, bool cond);
bool bytes_are_equal(const char* a, const char* b, size_t len);
bool is_id_unset(std::string id);

void put_netul(char* data, uint64_t num);
void put_netui(char* data, uint32_t num);
void put_netus(char* data, uint16_t num);
void put_netf(char* data, float num);
void put_netd(char* data, double num);

uint64_t get_netul(const char* data);
uint32_t get_netui(const char* data);
uint16_t get_netus(const char* data);
float get_netf(const char* data);
double get_netd(const char* data);

