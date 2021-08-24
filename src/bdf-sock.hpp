
#pragma once

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <bdf/Bdf.hpp>
#include <string>
#include <thread>
#include <mutex>
#include <queue>

template <typename T>
class BdfSock
{
private:

	std::string ip;
	std::thread handle;
	std::queue<Bdf::BdfReader*> queue;
	std::mutex mtx;

	bool is_ready = false;
	bool data_set;
	int sockfd;
	T data;
	
	void loop()
	{
		is_ready = true;

		while(connected())
		{
			char size_buff[4];
			int size = 0;

			if(read(sockfd, size_buff, 4) != 4)
			{
				close();
				return;
			}
		
			for(int i = 0; i < 4; i++)
			{
				size <<= 8;
				size ^= size_buff[i] & 255;
			}

			if(size <= 0)
			{
				continue;
			}

			char* data_buff = new char[size];

			int r = read(sockfd, data_buff, size);

			if(r != size)
			{
				close();

				delete[] data_buff;
				
				return;
			}

			Bdf::BdfReader* reader = new Bdf::BdfReader(data_buff, size);
			
			delete[] data_buff;

			mtx.lock();
			{
				queue.push(reader);
			}
			mtx.unlock();
		}
	}

	void connect(std::string address, int port)
	{
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		
		mtx.lock();
		{
			if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
			{
				std::cout << "Socket creation failed\n";
				is_ready = true;
				sockfd = -1;
				return;
			}

			if(inet_pton(AF_INET, address.c_str(), &addr.sin_addr) <= 0)
			{
				std::cout << "Invalid address\n";
				is_ready = true;
				close();
				return;
			}

			if(::connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
			{
				std::cerr << "Connection failed\n";
				is_ready = true;
				close();
				return;
			}
		}
		mtx.unlock();
		
		loop();
	}

public:

	BdfSock(int fd)
	{
		sockfd = fd;
		handle = std::thread(&BdfSock::loop, this);
		data_set = false;

		struct sockaddr_in addr;
		socklen_t addr_size = sizeof(addr);
		getpeername(sockfd, (struct sockaddr*)&addr, &addr_size);

		ip = std::string(inet_ntoa(addr.sin_addr));
	}

	BdfSock(std::string address, int port)
	{
		sockfd = -1;
		handle = std::thread(&BdfSock::connect, this, address, port);
		data_set = false;
		ip = address;
	}

	~BdfSock()
	{
		close();
		
		if(handle.joinable())
		{
			handle.detach();
		}
	}

	Bdf::BdfReader* poll()
	{
		if(!connected())
		{
			return nullptr;
		}
			
		Bdf::BdfReader* reader;
		
		mtx.lock();
		{
			if(queue.empty())
			{
				reader = nullptr;
			}

			else
			{
				reader = queue.front();
				queue.pop();
			}
		}
		mtx.unlock();

		return reader;
	}

	void send(Bdf::BdfReader* reader)
	{
		if(!connected())
		{
			return;
		}
		
		int size;
		char* data;

		reader->serialize(&data, &size);

		char size_buff[4] = {
			(char)((size >> 24) & 255),
			(char)((size >> 16) & 255),
			(char)((size >> 8) & 255),
			(char)(size & 255),
		};

		if(write(sockfd, size_buff, 4) != 4)
		{
			delete[] data;
			close();
		}

		if(write(sockfd, data, size) != size)
		{
			delete[] data;
			close();
		}

		delete[] data;
	}

	bool connected()
	{
		return (sockfd != -1);
	}

	bool ready()
	{
		return is_ready;
	}
	
	void close()
	{
		if(connected())
		{
			::shutdown(sockfd, SHUT_RDWR);
			sockfd = -1;
		}
	}

	std::string getIP()
	{
		return ip;
	}

	T* getData()
	{
		return &data;
	}

	bool dataIsSet()
	{
		return data_set;
	}

	void setData()
	{
		data_set = true;
	}
};

