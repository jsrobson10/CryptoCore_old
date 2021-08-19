
#include "http.hpp"
#include "web.hpp"
#include "sig.hpp"
#include "address.hpp"
#include "network.hpp"
#include "transaction.hpp"
#include "helpers.hpp"
#include "config.hpp"
#include "base58.hpp"
#include "cpu.hpp"

#include <bdf/Bdf.hpp>
#include <iostream>
#include <fstream>
#include <cstring>

#include <unistd.h>
#include <signal.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace Bdf;

static void display_help(const char** vargs)
{
	std::cerr << "Usage: " << vargs[0] << " ...\n";
	std::cerr << "  --help                  Display this message.\n";
	std::cerr << "  --generate-new          Generate a new header file for a new web. Useful for making altcoins.\n";
	std::cerr << "  --port <num>            Listen on a different p2p port (default is 44554).\n";
	std::cerr << "  --http-port <num>       Listen on a different http port (default is 44555).\n";
	std::cerr << "  --connect <ip> <port?>  Connect to the given peer. Will use the default port if none is given.\n";
	std::cerr << "\n";
}

int main(int cargs, const char** vargs)
{
	int port = 44554;
	int http_port = 44555;

	int peer_port = 0;
	std::string peer_ip;

	cpu::init();
	config::load();

	for(int i = 1; i < cargs; i++)
	{
		try
		{
			std::string arg = vargs[i];
	
			if(arg == "--generate-new")
			{
				web::generate_new();
				return 0;
			}
	
			else if(arg == "--port" && i < cargs - 1)
			{
				i += 1;
				port = std::stoi(vargs[i]);
			}

			else if(arg == "--http-port" && i < cargs - 1)
			{
				i += 1;
				http_port = std::stoi(vargs[i]);
			}

			else if(arg == "--connect" && i < cargs - 1)
			{
				peer_ip = std::string(vargs[i+1]);

				if(i < cargs - 2)
				{
					peer_port = std::stoi(vargs[i+2]);

					i += 2;
				}

				else
				{
					i += 1;
				}
			}
	
			else
			{
				display_help(vargs);
				return 1;
			}
		}

		catch(std::exception& e)
		{
			display_help(vargs);
			return 1;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	web::init();
	network::init(port);
	http::init(http_port);
		
	if(peer_port > 0)
	{
		network::connect(peer_ip, peer_port);
	}

	int c = 0;
	uint64_t cycle = 0;

	for(;;)
	{
		usleep(1000);

		network::update();
		http::update();

		if(cycle % 1000 == 0)
		{
			web::update();
		}

		cycle += 1;
	}

	web::cleanup();
	http::cleanup();
}
