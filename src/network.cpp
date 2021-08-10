
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

namespace network
{
	Control control;
	BdfServer<Client>* server;
	std::list<std::string> banned;
	std::queue<Bdf::BdfReader*> broadcast_queue;
	std::queue<Peer> peer_connect_queue;
	int connection_port;
};

const int network_cap = 3;

void network::init(int port)
{
	server = new BdfServer<Client>(port);
	connection_port = port;
}

void network::broadcast(BdfReader* reader)
{
	broadcast_queue.push(reader);
}

void network::ban(BdfSock<network::Client>* connection)
{
	network::Client* client = connection->getData();
	
	if(!isBanned(client->ip))
	{
		std::cerr << "Client with IP " << client->ip << " has been banned.\n";

		banned.push_front(client->ip);
	}

	connection->close();
}

bool network::isBanned(std::string ip)
{
	for(std::string& check : banned)
	{
		if(check == ip)
		{
			return true;
		}
	}

	return false;
}

bool network::isConnected(std::string ip, int port)
{
	server->lock();
	{
		std::list<BdfSock<network::Client>*>& connections = server->getConnections();

		for(BdfSock<network::Client>* connection : connections)
		{
			if(connection->connected() && connection->dataIsSet())
			{
				network::Client* data = connection->getData();

				if(data->ip == ip && data->port == port)
				{
					server->unlock();
					return true;
				}
			}
		}
	}

	server->unlock();

	return false;
}

void network::connect(std::string ip, int port)
{
	if(isConnected(ip, port) || isBanned(ip))
	{
		return;
	}

	BdfSock<network::Client>* connection = server->connect(ip, port);
	network::Client* data = connection->getData();

	data->ip = connection->getIP();
	data->port = port;
	data->state = network::State::NEW;
	data->ping = get_micros();

	connection->setData();
}

void network::handleConnection(BdfSock<network::Client>* connection)
{
	BdfReader* reader_recv;
	network::Client* client = connection->getData();

	// setup any new connections and ping the peer to get the time and ip
	if(!connection->dataIsSet() || client->state == network::State::NEW)
	{
		// setup the new connection
		client->state = network::State::PINGING;
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

			auto connections = server->getConnections();

			for(auto connection : connections)
			{
				if(connection->ready() && connection->connected() && connection->dataIsSet())
				{
					network::Client* client = connection->getData();

					if(client->state != network::State::ESTABLISHED)
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
			if(client->state != network::State::PINGING)
			{
				delete reader_recv;
				continue;
			}

			client->state = network::State::ESTABLISHED;
			client->port = nl->get("port")->getInteger();
			client->ping = get_micros() - client->ping;
		}

		// peer discovery
		if(method == "peers" || method == "pong")
		{
			if(server->count() >= network_cap)
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
					network::Peer peer;
					peer.ip = ip;
					peer.port = port;

					peer_connect_queue.push(peer);
				}

				peer_o = peer_o->next;
			}
		}

		// new raw transaction
		else if(method == "newtransaction")
		{
			char* data;
			int len;

			nl->get("data")->getByteArray(&data, &len);

			Transaction* t = new Transaction(data, len, nullptr, nullptr);
			
			int result = control.process_new_transaction(t);

			// illegal
			if(result == -1)
			{
				ban(connection);
			}

			// broadcast
			else if(result == 1)
			{
				BdfReader* reader_b = new BdfReader();
				BdfObject* bdf_b = reader_b->getObject();
				BdfNamedList* nl_b = bdf_b->getNamedList();

				nl_b->get("method")->setString("newtransaction");
				nl_b->get("data")->setByteArray(data, len);
				
				broadcast(reader_b);
			}
			
			delete[] data;
		}

		delete reader_recv;
	}
}

void network::update()
{
	server->lock();
	{
		auto connections = server->getConnections();
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

				if(connection->dataIsSet() && connection->getData()->state != network::State::ESTABLISHED)
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
				network::Peer peer = peer_connect_queue.front();
				peer_connect_queue.pop();
	
				if(!isConnected(peer.ip, peer.port) && !isBanned(peer.ip) && server->count() < network_cap)
				{
					server->connect(peer.ip, peer.port);
					std::cerr << "Connected to " << peer.ip << ":" << peer.port << std::endl;
				}
			}
		}

		int connection_count = server->count();

		// remove connections if above the limit but keep some connections with high ping
		if(connection_count > network_cap)
		{
			unsigned long ping_max_last = 0xffffffffffffffff;
			BdfSock<network::Client>* connection_max_last = NULL;

			for(int i = 0; i < connection_count / 2; i++)
			{
				unsigned long ping_max = 0;
				BdfSock<network::Client>* connection_max = NULL;
			
				for(auto connection : connections)
				{
					if(!connection->ready() || !connection->dataIsSet())
					{
						continue;
					}
	
					network::Client* data = connection->getData();

					if(data->state != network::State::ESTABLISHED)
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

		server->cullConnections();
	}
	server->unlock();
}

int network::getConnections()
{
	return server->count();
}
