
#pragma once

#include "bdf-sock.hpp"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <functional>
#include <iostream>
#include <list>
#include <thread>
#include <mutex>

template <typename T>
class BdfServer
{
private:
	
	std::thread handle;
	std::list<BdfSock<T>*> connections;
	std::mutex mtx;
	
	size_t addrlen;
	struct sockaddr_in addr;
	int mtx_local = 0;
	int sockfd;
	int port;

	void loop()
	{
		while(alive())
		{
			int sock_new = accept(sockfd, (struct sockaddr*)&addr, (socklen_t*)&addrlen);
			
			if(sock_new < 0)
			{
				std::cerr << "Connection failed\n";
				continue;
			}

			mtx.lock();
			{
				BdfSock<T>* connection = new BdfSock<T>(sock_new);
				connections.push_front(connection);
			}
			mtx.unlock();
		}
	}
	
public:

	BdfServer(int port)
	{
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

		this->port = port;

		int opt = 1;

		if(sockfd <= 0)
		{
			sockfd = -1;
			std::cerr << "Socket creation failed\n";
			return;
		}

		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
		{
			close();
			std::cerr << "Setsockopt failed\n";
			return;
		}

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);
		addrlen = sizeof(addr);

		if(bind(sockfd, (struct sockaddr*)&addr, addrlen) < 0)
		{
			close();
			std::cerr << "Socket bind failed\n";
			return;
		}

		if(listen(sockfd, 3) < 0)
		{
			close();
			std::cerr << "Socket listen failed\n";
			return;
		}

		handle = std::thread(&BdfServer::loop, this);
	}

	~BdfServer()
	{
		if(handle.joinable())
		{
			handle.detach();
		}
		
		close();
			
		for(auto it = connections.begin(); it != connections.end();)
		{
			auto last = it++;

			delete *last;
			connections.erase(last);
		}
	}

	void cullConnections()
	{
		lock();
		{
			for(auto it = connections.begin(); it != connections.end();)
			{
				if(!(*it)->ready())
				{
					continue;
				}

				if((*it)->connected())
				{
					it++;
				}

				else
				{
					auto last = it++;

					delete *last;
					connections.erase(last);
				}
			}
		}
		unlock();
	}

	void lock()
	{
		if(mtx_local == 0)
		{
			mtx.lock();
		}

		mtx_local += 1;
	}

	void unlock()
	{
		if(mtx_local == 1)
		{
			mtx.unlock();
		}

		mtx_local -= 1;
	}

	std::list<BdfSock<T>*>& getConnections()
	{
		return connections;
	}

	BdfSock<T>* connect(std::string ip, int port)
	{
		BdfSock<T>* connection = new BdfSock<T>(ip, port);
		
		connections.push_front(connection);
		return connection;
	}

	void close()
	{
		::close(sockfd);
		sockfd = -1;
	}

	bool alive()
	{
		return (sockfd != -1);
	}

	int count()
	{
		return connections.size();
	}
};

