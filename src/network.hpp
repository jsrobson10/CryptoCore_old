
#pragma once

#include "control.hpp"
#include "bdf-server.hpp"

#include <list>
#include <queue>
#include <string>

namespace network
{
	enum State
	{
		NEW, PINGING, ESTABLISHED
	};
		
	struct Client
	{
		State state;
		std::string ip;
		unsigned long ping;
		int port;
	};

	struct Peer
	{
		std::string ip;
		int port;
	};
	
	void handleConnection(BdfSock<Client>* connection);

	void init(int port);
	void cleanup();
	
	void update();
	void ban(BdfSock<Client>* connection);
	void broadcast(Bdf::BdfReader* reader);
	void connect(std::string ip, int port);

	int getConnections();
	bool isBanned(std::string ip);
	bool isConnected(std::string ip, int port);
};

