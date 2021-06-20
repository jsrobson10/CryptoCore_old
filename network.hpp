
#pragma once

#include "bdf-server.hpp"

#include <list>
#include <queue>
#include <string>

class Network
{
private:

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
	
	BdfServer<Client> server;
	std::list<std::string> banned;
	std::queue<Bdf::BdfReader*> broadcast_queue;
	std::queue<Peer> peer_connect_queue;
	int connection_port;

	void handleConnection(BdfSock<Client>* connection);

public:
	
	Network(int port);
	
	void update();
	void ban(BdfSock<Client>* connection);
	void broadcast(Bdf::BdfReader* reader);
	void connect(std::string ip, int port);

	int getConnections();
	bool isBanned(std::string ip);
	bool isConnected(std::string ip, int port);
};

