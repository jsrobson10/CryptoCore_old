
#pragma once

#include <string>

unsigned long get_micros();
void get_random_bytes(char* data, size_t len);
std::string to_hex(const char* data, size_t len);
std::string to_hex(std::string data);
std::string display_coins(uint64_t coins);
std::string calc_indent(int amount);

void put_netl(char* data, uint64_t num);
void put_neti(char* data, uint32_t num);
void put_nets(char* data, uint16_t num);
void put_netf(char* data, float num);
void put_netd(char* data, double num);

uint64_t get_netl(const char* data);
uint32_t get_neti(const char* data);
uint16_t get_nets(const char* data);
float get_netf(const char* data);
double get_netd(const char* data);

