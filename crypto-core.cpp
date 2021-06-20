
#include "network.hpp"
#include "cryp256.h"

#include <bdf/Bdf.hpp>
#include <iostream>
#include <fstream>
#include <cstring>

#include <unistd.h>
#include <signal.h>

using namespace Bdf;

CRYP256_word target[] = {
	0x000000ff,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};

CRYP256_word id[8];

char block[] = "Hello, World!";

std::ifstream random_device("/dev/random", std::ios::binary);

int main(int cargs, const char** vargs)
{
	int port = 44554;

	std::string peer_ip;
	int peer_port = 44554;
	bool peer_initial = false;

	if(cargs >= 2 && cargs <= 4)
	{
		port = std::stoi(vargs[1]);
	}

	if(cargs >= 3 && cargs <= 4)
	{
		peer_ip = std::string(vargs[2]);
		peer_initial = true;
	}

	if(cargs == 4)
	{
		peer_port = std::stoi(vargs[3]);
	}

	else if(cargs > 4)
	{
		std::cerr << "Usage: ";
		std::cerr << vargs[0];
		std::cerr << " <port> <peer ip> <peer port>\n\n";
		return 1;
	}

	signal(SIGPIPE, SIG_IGN);
		
	Network network(port);

	if(peer_initial)
	{
		network.connect(peer_ip, peer_port);
	}

	int c = 0;

	for(;;)
	{
		usleep(1000);

		network.update();

		c = (c + 1) % 1000;

		if(c == 0)
		{
			std::cerr << "Connected: " << network.getConnections() << std::endl;
		}
	}
}
