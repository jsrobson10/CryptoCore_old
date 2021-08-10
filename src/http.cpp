
#include "http.hpp"
#include "helpers.hpp"
#include "transaction.hpp"
#include "web.hpp"
#include "sig.hpp"
#include "address.hpp"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <queue>
#include <mutex>
#include <thread>
#include <iostream>
#include <string>

namespace http
{
	Json::StreamWriterBuilder wbuilder;	
	std::queue<Request*> requests;
	std::thread handle;
	std::mutex mtx;

	socklen_t addrlen;
	struct sockaddr_in addr;

	int sockfd;
	bool running;

	std::string INVALID_REQUEST = std::string("")+
			"HTTP/1.1 400 Error\n"+
			"Content-Type: application/json\n"+
			"Content-Length: 29\n"+
			"Connection: close\n"+
			"\n{\"error\": \"invalid request\"}\n";
	
	void run();
};

std::string http::generate_error(std::string message)
{
	Json::Value msg_j;
	msg_j["error"] = message;
	
	std::string data = Json::writeString(wbuilder, msg_j);

	return std::string()+
			"HTTP/1.1 400 Error\n"+
			"Content-Type: application/json\n"+
			"Content-Length: "+std::to_string(data.length()+1)+"\n"+
			"Connection: close\n\n"+data+"\n";
}

void http::run()
{
	running = true;
	
	while(running)
	{
		int sock_new = accept(sockfd, (struct sockaddr*)&addr, &addrlen);

		if(sock_new < 0)
		{
			std::cerr << "Connection failed\n";
			continue;
		}

		new http::Request(sock_new);
	}
}

void http::init(int port)
{
	wbuilder["indentation"] = "";

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if(sockfd <= 0)
	{
		sockfd = -1;
		std::cerr << "Socket creation failed\n";
		return;
	}

	int opt = 1;

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
	{
		cleanup();
		std::cerr << "Setsockopt failed\n";
		return;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	addrlen = sizeof(addr);

	if(bind(sockfd, (struct sockaddr*)&addr, addrlen) < 0)
	{
		cleanup();
		std::cerr << "Sock bind fained\n";
		return;
	}

	if(listen(sockfd, 3) < 0)
	{
		cleanup();
		std::cerr << "Sock listen failed\n";
		return;
	}

	handle = std::thread(&http::run);

	std::cerr << "HTTP server listening on " << port << std::endl;
}

void http::update()
{
	for(;;)
	{
		Request* req;
		
		mtx.lock();
		{
			if(requests.empty())
			{
				mtx.unlock();
				return;
			}

			req = requests.front();
			requests.pop();
		}
		mtx.unlock();

		std::string at = to_lower(req->pathv[0]);

		if(at == "")
		{
			
		}

		else if(at == "generatewallet")
		{
			std::string prikey = sig::generate();
			std::string pubkey = sig::getpubkey(prikey);
			std::string address = address::frompubkey(pubkey);

			Json::Value value;

			value["prikey"] = to_hex(prikey);
			value["pubkey"] = to_hex(pubkey);
			value["address"] = address::fromhash(address);

			req->respond(value);
			
			delete req;
			continue;
		}

		else if(at == "listtransactions")
		{
			web::show_all();
		}

		else if(at == "gettransaction" && req->pathc >= 2)
		{
			std::string txid = req->pathv[1];

			if(txid.length() != 64)
			{
				Json::Value v;
				v["error"] = "invalid txid";

				req->respond(v);

				delete req;
				continue;
			}

			std::string txid_bytes = from_hex(txid);
			Transaction* tx = web::get_transaction(txid_bytes);

			if(tx == nullptr)
			{
				Json::Value v;
				v["error"] = "transaction not found";
				v["txid"] = txid;

				req->respond(v);

				delete req;
				continue;
			}

			Json::Value v;
			v["transaction"] = tx->to_json();

			req->respond(v);

			delete tx;
			delete req;
			continue;
		}

		std::string error = generate_error("invalid method");
		write(req->sockfd, error.c_str(), error.length());

		delete req;
	}
}

void http::cleanup()
{
	handle.detach();
	running = false;
}

http::Request::Request(int fd)
{
	sockfd = fd;
	handle = std::thread(&http::Request::run, this);
	pathv = nullptr;
}

http::Request::~Request()
{
	if(pathv != nullptr)
	{
		delete[] pathv;
	}
	
	handle.detach();
	close();
}

void http::Request::respond(const Json::Value& value)
{
	const char c = '\n';

	std::string data = Json::writeString(wbuilder, value);
	std::string header = std::string()+
			"HTTP/1.1 200 OK\n"+
			"Content-Type: application/json\n"+
			"Content-Length: " + std::to_string(data.length()+1) + "\n"+
			"Connection: close\n\n";

	write(sockfd, header.c_str(), header.length());
	write(sockfd, data.c_str(), data.length());
	write(sockfd, &c, 1);
}

void http::Request::respond(int status, std::string status_msg, std::string headers, std::string data)
{
	std::string header = std::string()+
			"HTTP/1.1 "+std::to_string(status)+" "+status_msg+"\n"+headers+
			"Content-Length: "+std::to_string(data.length())+
			"\n\n"+data;

	write(sockfd, header.c_str(), header.length());
}

void http::Request::close()
{
	if(sockfd != -1)
	{
		::close(sockfd);
		sockfd = -1;
	}
}

void http::Request::run()
{
	size_t content_length = 0;
	std::string http_method;
	std::string http_path;

	bool first = true;
	char buffer[1024];
	char* buff_upto = buffer;
	int newlines = 0;
	char buff_c;

	uint64_t start = get_micros();

	for(;;)
	{
		read(sockfd, &buff_c, 1);

		// ignore these
		if(buff_c == '\r')
		{
			continue;
		}

		if(buff_c == '\n')
		{
			newlines += 1;

			size_t buff_len = (size_t)(buff_upto - buffer);
			std::string data(buffer, buff_len);

			if(first) // should be somethig like "METHOD /path HTTP/1.1"
			{
				std::string header[3];
				bool last_was_break = true;
				int at = 0;

				for(auto i = data.begin(); i != data.end(); i++)
				{
					char c = *i;

					if(c == ' ' || c == '\t')
					{
						if(!last_was_break)
						{
							last_was_break = true;
							at += 1;
	
							if(at == 3)
							{
								break;
							}
						}
					}

					else
					{
						last_was_break = false;
						header[at] += c;
					}
				}

				if(at != 2 || header[2] != "HTTP/1.1" || header[1].length() == 0 || !(header[1][0] == '/' || header[1][0] == '\\'))
				{
					write(sockfd, INVALID_REQUEST.c_str(), INVALID_REQUEST.length());

					delete this;
					return;
				}

				http_method = header[0];
				http_path = header[1];

				first = false;
			}

			else
			{
				// split the data into the header name and header value. Will be "name...:...value"
				std::string header_key;
				std::string header_value;
				int step = 0;

				for(auto at = data.begin(); at != data.end(); at++)
				{
					char c = *at;

					// split the header into a key: value pair
					switch(step)
					{
						case 0:
						{
							if(c == ' ' || c == '\t')
							{
								step = 1;
							}

							else if(c == ':')
							{
								step = 2;
							}

							else
							{
								if(c >= 'A' && c <= 'Z')
								{
									c += 32;
								}

								header_key += c;
							}

							break;
						}

						case 1:
						{
							if(c == ':')
							{
								step = 2;
							}

							break;
						}

						case 2:
						{
							if(c != ' ' && c != '\t')
							{
								step = 3;
							}

							else
							{
								break;
							}
						}

						case 3:
						{
							header_value += c;

							break;
						}
					}
				}

				// content length is the only thing we care about
				if(header_key == "content-length: ")
				{
					try
					{
						content_length = std::stol(header_value);
					}
					
					// catch any errors
					catch(std::exception& e)
					{
						write(sockfd, INVALID_REQUEST.c_str(), INVALID_REQUEST.length());

						delete this;
						return;
					}
				}
			}

			buff_upto = buffer;
		}

		else
		{
			// prevent a buffer overflow
			if(buff_upto >= buffer + 1024)
			{
				write(sockfd, INVALID_REQUEST.c_str(), INVALID_REQUEST.length());

				delete this;
				return;
			}

			*buff_upto = buff_c;
			buff_upto += 1;
			newlines = 0;
		}

		// 2 newlines is where the data starts
		if(newlines == 2)
		{
			// json data is read if the request is a POST request
			if(http_method == "POST")
			{
				// invalid content length or greater than the limit (1 MB)
				if(content_length <= 0 || content_length > 1048576)
				{
					write(sockfd, INVALID_REQUEST.c_str(), INVALID_REQUEST.length());

					delete this;
					return;
				}

				char* data = new char[content_length];

				read(sockfd, data, content_length);

				std::string errors;
				Json::CharReaderBuilder builder;
				auto reader = builder.newCharReader();
				
				if(!reader->parse(data, data + content_length, &value, &errors))
				{
					std::string response = generate_error("invalid json: " + errors);
					write(sockfd, response.c_str(), response.length());

					delete this;
					return;
				}

				delete[] data;
			}

			pathc = 0;
			char end_c = *(http_path.end() - 1);
			
			if(end_c == '\\' || end_c == '/')
			{
				http_path = http_path.substr(0, http_path.length() - 1);
			}

			// could be "/", "/path/to", or "/path/to/".
			// could also contain "\" instead of "/"
			for(auto at = http_path.begin(); at != http_path.end(); at++)
			{
				char c = *at;

				// break
				if(c == '\\' || c == '/')
				{
					pathc += 1;
				}
			}

			if(pathc == 0)
			{
				pathc = 1;
			}

			int path_at = 0;
			pathv = new std::string[pathc];
			buff_upto = buffer;

			for(auto at = http_path.begin() + 1; at < http_path.end(); at++)
			{
				char c = *at;

				// break
				if(c == '\\' || c == '/')
				{
					pathv[path_at++] = std::string(buffer, (size_t)(buff_upto - buffer));
					buff_upto = buffer;
				}

				else
				{
					*buff_upto = c;
					buff_upto += 1;
				}
			}
		
			if(buff_upto > buffer)
			{
				pathv[path_at] = std::string(buffer, (size_t)(buff_upto - buffer));
			}

			http::mtx.lock();
			http::requests.push(this);
			http::mtx.unlock();

			return;
		}
	}
}
