
#ifndef _CRYP256_H_
#define _CRYP256_H_

typedef unsigned int CRYP256_word;
typedef unsigned long CRYP256_size;

typedef struct CRYP256 CRYP256;

struct CRYP256
{
	CRYP256_word schedule[262144];
	CRYP256_word values[8];
	char buffer[64];
	CRYP256_size size;
	short upto;
};

void CRYP256_init(CRYP256* s);
void CRYP256_update(CRYP256* s, const char* data, CRYP256_size len);
void CRYP256_digest(CRYP256* s, char* data);

#endif
