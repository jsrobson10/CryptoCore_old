
#include "cryp256.h"
#include "cryp256-const.h"

/* CONSTANTS */

// square roots of first 8 primes
const CRYP256_word CRYP256_INIT[] =
{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/* FUNCTIONS */

void CRYP256_op_copy(void* to, const void* from, CRYP256_size len)
{
	void* end = to + len;

	while(to < end)
	{
		*(char*)to = *(const char*)from;

		to += 1;
		from += 1;
	}
}

void CRYP256_op_process_chunk(CRYP256* s)
{
	CRYP256_word* schedule = s->schedule;

	// copy all the data over to the schedule accounting for endianness
	for(int i = 0; i < 16; i++)
	{
		int i4 = i * 4;

		CRYP256_word w1 = s->buffer[i4] & 255;
		CRYP256_word w2 = s->buffer[i4+1] & 255;
		CRYP256_word w3 = s->buffer[i4+2] & 255;
		CRYP256_word w4 = s->buffer[i4+3] & 255;

		schedule[i] = (w1 << 24) | (w2 << 16) | (w3 << 8) | w4;
	}

	// fill in the last 262144 words of the message schedule
	for(int i = 16; i < 262144; i++)
	{
		CRYP256_word s1 = schedule[i - 2];
		CRYP256_word s2 = schedule[i - 15];
		CRYP256_word s3 = (s2 >> 7) ^ (s2 << 25) ^ (s2 >> 18) ^ (s2 << 14) ^ (s2 >> 3); // sigma0
		CRYP256_word s4 = (s1 >> 17) ^ (s1 << 15) ^ (s1 >> 19) ^ (s1 << 13) ^ (s1 >> 10); // sigma1
		schedule[i] = s3 + s4 + schedule[i - 7] + schedule[i - 16];
	}

	// make a copy of the values
	CRYP256_word a = s->values[0];
	CRYP256_word b = s->values[1];
	CRYP256_word c = s->values[2];
	CRYP256_word d = s->values[3];
	CRYP256_word e = s->values[4];
	CRYP256_word f = s->values[5];
	CRYP256_word g = s->values[6];
	CRYP256_word h = s->values[7];

	// compress the message schedule
	for(int i = 0; i < 262144; i++)
	{
		CRYP256_word s1 = (a >> 2) ^ (a << 30) ^ (a >> 13) ^ (a << 19) ^ (a >> 22) ^ (a << 10); // usigma0
		CRYP256_word s2 = (e >> 6) ^ (e << 26) ^ (e >> 11) ^ (e << 21) ^ (e >> 25) ^ (e << 7); // usigma1
		CRYP256_word t1 = s2 + ((e & f) ^ (~e & g)) + h + CRYP256_CONST[i] + schedule[i];
		CRYP256_word t2 = s1 + ((a & b) ^ (a & c) ^ (b & c));

		// move the values down and change them
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	// add the new values to the initial values
	s->values[0] += a;
	s->values[1] += b;
	s->values[2] += c;
	s->values[3] += d;
	s->values[4] += e;
	s->values[5] += f;
	s->values[6] += g;
	s->values[7] += h;
}

void CRYP256_init(CRYP256* s)
{
	CRYP256_op_copy(s->values, CRYP256_INIT, sizeof(CRYP256_word) * 8);

	s->upto = 0;
	s->size = 0;
}

void CRYP256_update(CRYP256* s, const char* data, CRYP256_size len)
{
	// process complete blocks as we update to make this streamable
	while(len + s->upto >= sizeof(s->buffer))
	{
		// calculate the amount of data to add to the buffer but dont overflow
		int a = sizeof(s->buffer) - s->upto;

		if(len < a)
		{
			a = len;
		}

		// move the data into the buffer
		CRYP256_op_copy(s->buffer + s->upto, data, a);

		CRYP256_op_process_chunk(s);

		len -= a;
		data += a;

		s->upto = 0;
		s->size += sizeof(s->buffer);
	}

	// add the smaller data to the end of the buffer
	CRYP256_op_copy(s->buffer + s->upto, data, len);
	s->upto += len;
}

void CRYP256_digest(CRYP256* s, char* buffer)
{
	// pad the last chunk
	CRYP256_size upto = s->upto;
	CRYP256_size size = s->size + upto;
	CRYP256_size size_bits = size * 8;

	// add a 1 after the data
	s->buffer[upto] = 1 << 7;

	if(upto < 56)
	{
		// fill with zeros
		for(int i = upto + 1; i < 56; i++)
		{
			s->buffer[i] = (char)0;
		}
	}

	else
	{
		// fill with zeros
		for(int i = upto + 1; i < 64; i++)
		{
			s->buffer[i] = (char)0;
		}

		// process the first padded chunk
		CRYP256_op_process_chunk(s);

		// fill the next buffer with zeros
		for(int i = 0; i < 56; i++)
		{
			s->buffer[i] = (char)0;
		}
	}

	// add the size
	for(int i = 63; i >= 56; i--)
	{
		s->buffer[i] = size_bits & 255;
		size_bits >>= 8;
	}

	// process the final padded chunk
	CRYP256_op_process_chunk(s);

	// copy the words into the buffer
	for(int i = 0; i < 8; i++)
	{
		int i4 = i * 4;

		buffer[i4  ] = (s->values[i] >> 24) & 255;
		buffer[i4+1] = (s->values[i] >> 16) & 255;
		buffer[i4+2] = (s->values[i] >> 8 ) & 255;
		buffer[i4+3] = (s->values[i]      ) & 255;
	}
}
