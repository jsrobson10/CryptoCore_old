
#pragma once

#include <json/json.h>

#include <thread>

namespace http
{
	class Request
	{
	public:
		
		int sockfd;
		Json::Value value;

		int pathc;
		std::string* pathv;
		
		Request(int sockfd);
		~Request();
		void respond(int status, std::string status_msg, std::string headers, std::string data);
		void respond(const Json::Value& value);
		void close();
	
	private:
		
		std::thread handle;
	
		void run();
	};

	std::string generate_error(std::string content);
	void init(int port);
	void update();
	void cleanup();
};
