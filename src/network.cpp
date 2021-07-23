
#include "helpers.hpp"
#include "network.hpp"
#include "bdf/Bdf.hpp"

using namespace Bdf;

/*
 *
 * need to:
 *
 * - maintain a list of peers and pings
 * - keep track of broadcasted packets and their IDs, share them among peers
 *   but ignore the packet if the packet ID has already been seen
 * - maintain a banlist of peers that misbehave
 * - detect and ban misbehaving peers:
 *    - sending bad packets
 * - check all packets to make sure they're valid, ignore and ban if they're not
 * - preference connecting to peers with low ping, so drop connections with peers
 *   based on connection cap and ping
 *
 */

const int network_cap = 3;

Network::Network(int port) : server(port)
{
	connection_port = port;
}

void Network::broadcast(BdfReader* reader)
{
	broadcast_queue.push(reader);
}

void Network::ban(BdfSock<Network::Client>* connection)
{
	Network::Client* client = connection->getData();
	
	if(!isBanned(client->ip))
	{
		std::cerr << "Client with IP " << client->ip << " has been banned.\n";

		banned.push_front(client->ip);
	}

	connection->close();
}

bool Network::isBanned(std::string ip)
{
	for(std::string check : banned)
	{
		if(check == ip)
		{
			return true;
		}
	}

	return false;
}

bool Network::isConnected(std::string ip, int port)
{
	server.lock();
	{
		std::list<BdfSock<Network::Client>*>& connections = server.getConnections();

		for(BdfSock<Network::Client>* connection : connections)
		{
			if(connection->connected() && connection->dataIsSet())
			{
				Network::Client* data = connection->getData();

				if(data->ip == ip && data->port == port)
				{
					server.unlock();
					return true;
				}
			}
		}
	}

	server.unlock();

	return false;
}

void Network::connect(std::string ip, int port)
{
	if(isConnected(ip, port) || isBanned(ip))
	{
		return;
	}

	BdfSock<Network::Client>* connection = server.connect(ip, port);
	Network::Client* data = connection->getData();

	data->ip = connection->getIP();
	data->port = port;
	data->state = Network::State::NEW;
	data->ping = get_micros();

	connection->setData();
}

void Network::handleConnection(BdfSock<Network::Client>* connection)
{
	BdfReader* reader_recv;
	Network::Client* client = connection->getData();

	// setup any new connections and ping the peer to get the time and ip
	if(!connection->dataIsSet() || client->state == Network::State::NEW)
	{
		// setup the new connection
		client->state = Network::State::PINGING;
		client->ip = connection->getIP();
		client->ping = get_micros();
		client->port = 0;

		// abort if they're banned
		if(isBanned(client->ip))
		{
			connection->close();
			return;
		}
	
		// ping the connection
		connection->setData();

		BdfReader reader_send;
		BdfObject* o_s = reader_send.getObject();
		BdfNamedList* nl_s = o_s->getNamedList();

		nl_s->get("method")->setString("ping");

		connection->send(&reader_send);
	}

	// recieve new data from peers
	while((reader_recv = connection->poll()) != NULL)
	{
		//reader_recv->serializeHumanReadable(std::cout);

		BdfObject* o = reader_recv->getObject();
		BdfNamedList* nl = o->getNamedList();

		std::string method = nl->get("method")->getString();

		// respond to pings
		if(method == "ping")
		{
			BdfReader reader_send;
			BdfObject* o_s = reader_send.getObject();
			BdfNamedList* nl_s = o_s->getNamedList();

			nl_s->get("method")->setString("pong");
			nl_s->get("port")->setInteger(connection_port);
			BdfList* peers_l = nl_s->get("peers")->getList();

			auto connections = server.getConnections();

			for(auto connection : connections)
			{
				if(connection->ready() && connection->connected() && connection->dataIsSet())
				{
					Network::Client* client = connection->getData();

					if(client->state != Network::State::ESTABLISHED)
					{
						continue;
					}

					BdfObject* peer_o = o_s->newObject();
					BdfNamedList* peer_nl = peer_o->getNamedList();

					peer_nl->get("ip")->setString(client->ip);
					peer_nl->get("port")->setInteger(client->port);

					peers_l->add(peer_o);
				}
			}

			connection->send(&reader_send);
		}

		// recieve ping responses
		else if(method == "pong")
		{
			if(client->state != Network::State::PINGING)
			{
				delete reader_recv;
				continue;
			}

			client->state = Network::State::ESTABLISHED;
			client->port = nl->get("port")->getInteger();
			client->ping = get_micros() - client->ping;
		}

		// peer discovery
		if(method == "peers" || method == "pong")
		{
			if(server.count() >= network_cap)
			{
				delete reader_recv;
				continue;
			}

			BdfList* peers_l = nl->get("peers")->getList();
			BdfList::Item* peer_o = peers_l->getStart();

			while(peer_o != NULL)
			{
				BdfNamedList* peer_nl = peer_o->object->getNamedList();

				std::string ip = peer_nl->get("ip")->getString();
				int port = peer_nl->get("port")->getInteger();

				if(port > 0 && port <= 65535)
				{
					Network::Peer peer;
					peer.ip = ip;
					peer.port = port;

					peer_connect_queue.push(peer);
				}

				peer_o = peer_o->next;
			}
		}

		delete reader_recv;
	}
}

void Network::update()
{
	server.lock();
	{
		auto connections = server.getConnections();
		bool all_ready = true;

		// handle messages from all connections
		for(auto connection : connections)
		{
			if(!connection->ready())
			{
				all_ready = false;
				continue;
			}
			
			if(connection->connected())
			{
				handleConnection(connection);

				if(connection->dataIsSet() && connection->getData()->state != Network::State::ESTABLISHED)
				{
					all_ready = false;
				}
			}
		}

		if(all_ready)
		{
			// add peers in the queue once all new peers are ready
			if(!peer_connect_queue.empty())
			{
				Network::Peer peer = peer_connect_queue.front();
				peer_connect_queue.pop();
	
				if(!isConnected(peer.ip, peer.port) && !isBanned(peer.ip) && server.count() < network_cap)
				{
					server.connect(peer.ip, peer.port);
					std::cerr << "Connected to " << peer.ip << ":" << peer.port << std::endl;
				}
			}
		}

		int connection_count = server.count();

		// remove connections if above the limit but keep some connections with high ping
		if(connection_count > network_cap)
		{
			unsigned long ping_max_last = 0xffffffffffffffff;
			BdfSock<Network::Client>* connection_max_last = NULL;

			for(int i = 0; i < connection_count / 2; i++)
			{
				unsigned long ping_max = 0;
				BdfSock<Network::Client>* connection_max = NULL;
			
				for(auto connection : connections)
				{
					if(!connection->ready() || !connection->dataIsSet())
					{
						continue;
					}
	
					Network::Client* data = connection->getData();

					if(data->state != Network::State::ESTABLISHED)
					{
						continue;
					}

					if(data->ping >= ping_max && data->ping < ping_max_last)
					{
						ping_max = data->ping;
						connection_max = connection;
					}
				}

				if(connection_max != nullptr)
				{
					ping_max_last = ping_max;
					connection_max_last = connection_max;
				}
			}

			if(connection_max_last != nullptr)
			{
				connection_max_last->close();
			}
		}

		server.cullConnections();
	}
	server.unlock();
}

int Network::getConnections()
{
	return server.count();
}
