
#include "base58.hpp"
#include "network.hpp"
#include "transaction.hpp"
#include "ec.hpp"
#include "helpers.hpp"

#include <bdf/Bdf.hpp>
#include <iostream>
#include <fstream>
#include <cstring>

#include <unistd.h>
#include <signal.h>

using namespace Bdf;

int main(int cargs, const char** vargs)
{
	std::string t = "qwerty";
	
	std::cout << base58::encode(t.c_str(), t.length()) << std::endl;

	/*ec::init();

	std::string key_pri1 = ec::generate();
	std::string key_pri2 = ec::generate();
	std::string key_address1 = ec::get_address(key_pri1);
	std::string key_address2 = ec::get_address(key_pri2);

	Transaction t;

	t.add_input(key_pri1, 5.2f);
	t.add_output(key_address2, 4.2f);
	t.finalize();

	std::cout << t.to_string() << "\n";

	size_t tx_len = t.serialize_len();
	char* tx = new char[tx_len];
	t.serialize(tx);

	std::cout << to_hex(tx, tx_len) << "\n";*/

	/*int port = 44554;

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
	}*/
}
