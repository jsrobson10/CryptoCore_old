
#include "cpu.hpp"

bool cpu::avx2 = false;

void cpu::init()
{
	if(__builtin_cpu_supports("avx2"))
	{
		avx2 = true;
	}
}

