
#include "helpers.hpp"

#include <sys/time.h>

unsigned long get_micros()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}
