
#include "http.hpp"
#include "helpers.hpp"
#include "transaction.hpp"
#include "web.hpp"
#include "sig.hpp"
#include "address.hpp"
#include "config.hpp"

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

	Json::Value handle_req(Request* req, std::string at);

	std::string INVALID_REQUEST = std::string("")+
			"HTTP/1.1 400 Error\n"+
			"Content-Type: application/json\n"+
			"Content-Length: 29\n"+
			"Connection: close\n"+
			"\n{\"error\": \"invalid request\"}\n";
			
	const std::string COMMANDS[][3] =
	{
			{"help", "display this help message", ""},
			{"auth", "login to this service and set the cookie", "{\"auth\": key}"},
			{"logout", "delete your authentication cookie and log out", ""},
			{"generatewallet", "generate a new wallet along with the private key, public key, and wallet address", ""},
			{"getwallet", "get a wallets other details from its private key", "{\"prikey\": prikey} OR /getwallet/<prikey>"},
			{"gettransaction", "get a given transaction by its transaction ID", "{\"txid\": txid} OR /gettransaction/<txid>"},
			{"getaddress", "get information about an address, like the latest transaction and its balance", "{\"address\": address} OR /getaddress/<address>"},
			{"listoutputs", "find every time a transaction has been made to an address", "{\"address\": address, \"last\": last, \"limit\": limit} OR /listoutputs/<address>"},
			{"send", "generate a transaction and send funds from at least 1 wallet to at least 1 address", "{\"inputs\": [{\"prikey\": prikey, \"amount\": amount}...], \"outputs\": [{\"address\", address, \"amount\": amount}...]}"},
			{"getedgenodes", "get all current edge nodes", ""},
	};

	
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
			std::cout << "Connection failed\n";
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
		std::cout << "Socket creation failed\n";
		return;
	}

	int opt = 1;

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
	{
		cleanup();
		std::cout << "Setsockopt failed\n";
		return;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	addrlen = sizeof(addr);

	if(bind(sockfd, (struct sockaddr*)&addr, addrlen) < 0)
	{
		cleanup();
		std::cout << "Sock bind fained\n";
		return;
	}

	if(listen(sockfd, 3) < 0)
	{
		cleanup();
		std::cout << "Sock listen failed\n";
		return;
	}

	handle = std::thread(&http::run);

	std::cout << "HTTP server listening on http://127.0.0.1:" << port << "/" << std::endl;
	std::cout << "Authentication ID is " << config::http_auth << std::endl;
}

Json::Value http::handle_req(Request* req, std::string at)
{
	if(at == "")
	{
		const std::string content = "<html><body><p>You are currently logged in.</p><form action='/logout'><button>Log Out</button></body></html>";
		std::string headers = "Content-Type: text/html; charset=utf-8\nContent-Length: "+std::to_string(content.length())+"\n";

		req->respond(200, "OK", headers, content);

		return Json::Value();
	}

	else if(at == "help")
	{
		Json::Value v;

		const int COMMANDS_LEN = sizeof(COMMANDS) / sizeof(COMMANDS[0]);

		for(int i = 0; i < COMMANDS_LEN; i++)
		{
			v[i]["method"] = COMMANDS[i][0];
			v[i]["desc"] = COMMANDS[i][1];

			if(COMMANDS[i][2] != "")
			{
				v[i]["usage"] = COMMANDS[i][2];
			}
		}

		return v;
	}

	else if(at == "auth")
	{
		if(req->value["key"] == config::http_auth)
		{
			req->respond(200, "OK", "Set-Cookie: auth="+config::http_auth+"; SameSite=Strict; HttpOnly\n", "");
		}

		else
		{
			req->respond(400, "Error", "", "");
		}

		return Json::Value();
	}

	else if(at == "logout")
	{
		const std::string CONTENT = std::string()+
				"<html><head><script>"+
				"setTimeout(() => {"+
				"window.location.replace('/');"+
				"}, 1500);"+
				"</script></head><body>"+
				"<p>logged out</p>"+
				"</body></html>";

		req->respond(200, "OK", "Set-Cookie: auth=\nContent-Type: text/html; charset=utf-8\nContent-Length: "+std::to_string(CONTENT.length())+"\n", CONTENT);

		return Json::Value();
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

		return value;
	}

	else if(at == "getwallet")
	{
		std::string prikey;

		if(req->pathc >= 2)
		{
			prikey = from_hex(req->pathv[1]);
		}

		else
		{
			prikey = from_hex(req->value["prikey"].asString());
		}

		if(prikey.length() != SIG_LEN_PRIKEY)
		{
			Json::Value v;
			v["error"] = "invalid prikey";

			return v;
		}

		std::string pubkey = sig::getpubkey(prikey);
		std::string address = address::frompubkey(pubkey);

		Json::Value value;

		value["prikey"] = to_hex(prikey);
		value["pubkey"] = to_hex(pubkey);
		value["address"] = address::fromhash(address);

		return value;
	}

	else if(at == "listtransactions")
	{
		web::show_all();
	}

	else if(at == "gettransaction")
	{
		std::string txid;

		if(req->pathc >= 2)
		{
			txid = req->pathv[1];
		}

		else
		{
			txid = req->value["txid"].asString();
		}

		if(txid.length() != 64)
		{
			Json::Value v;
			v["error"] = "invalid txid";
			v["txid"] = txid;

			return v;
		}

		std::string txid_bytes = from_hex(txid);
		Transaction* tx = web::get_transaction(txid_bytes);

		if(tx == nullptr)
		{
			Json::Value v;
			v["error"] = "transaction not found";
			v["txid"] = txid;

			return v;
		}

		Json::Value v;
		v["transaction"] = tx->to_json();

		delete tx;
		return v;
	}

	else if(at == "listoutputs")
	{
		std::string address;
		std::string from = "";
		int limit = 1024;

		if(req->pathc >= 2)
		{
			address = req->pathv[1];
		}

		else
		{
			address = req->value["address"].asString();
			from = req->value["from"].asString();
			limit = req->value["limit"].asInt();

			if(limit <= 0)
			{
				limit = 1024;
			}
		}

		if(!address::verify(address))
		{
			Json::Value v;
			v["error"] = "invalid address";
			v["address"] = address;

			return v;
		}

		std::list<Transaction*> transactions;
		web::find_outputs(transactions, address::gethash(address), "", 1024);

		int i = 0;
		Json::Value v;
		
		for(auto at = transactions.begin(); at != transactions.end(); at++)
		{
			v[i] = (*at)->to_json();
			i += 1;
			
			delete *at;
		}

		return v;
	}

	else if(at == "getaddress")
	{
		std::string address;

		if(req->pathc >= 2)
		{
			address = req->pathv[1];
		}

		else
		{
			address = req->value["address"].asString();
		}

		if(!address::verify(address))
		{
			Json::Value v;
			v["error"] = "invalid address";
			v["address"] = address;

			return v;
		}

		std::list<Transaction*> unconfirmed;
		uint64_t balance;
		Transaction* tx;
		Json::Value v;

		web::get_address_info(address::gethash(address), balance, tx, unconfirmed, 0);
		
		v["balance"] = std::to_string(balance);
		v["address"] = address;

		if(tx != nullptr)
		{
			v["tx"] = tx->to_json();

			delete tx;
		}

		return v;
	}

	else if(at == "getedgenodes")
	{
		Json::Value v;
		int i = 0;

		for(Transaction* tx : web::edge_nodes)
		{
			v[i] = tx->to_json();
			i += 1;
		}

		return v;
	}

	else if(at == "send")
	{
		Json::Value& inputs_j = req->value["inputs"];
		Json::Value& outputs_j = req->value["outputs"];

		int len_in = inputs_j.size();
		int len_out = inputs_j.size();

		uint64_t total_in = 0;
		uint64_t total_out = 0;

		Transaction tx_final;

		if(len_in < 1 || len_out < 1)
		{
			Json::Value v;
			v["error"] = "cannot have zero inputs/outputs";
			return v;
		}

		// make sure each input is valid and has enough funds
		// also get the sources to declare for each
		for(Json::Value::ArrayIndex i = 0; i != len_in; i++)
		{
			try
			{
				std::string prikey = from_hex(inputs_j[i]["prikey"].asString());
				uint64_t amount = std::stoul(inputs_j[i]["amount"].asString());

				if(prikey.length() != SIG_LEN_PRIKEY)
				{
					Json::Value v;
					v["error"] = "invalid prikey";
					return v;
				}

				if(amount == 0)
				{
					Json::Value v;
					v["error"] = "cannot have zero amount";
					return v;
				}

				if(amount + total_in < total_in)
				{
					Json::Value v;
					v["error"] = "insufficient funds";
					return v;
				}

				uint64_t balance;
				Transaction* tx;
				std::list<Transaction*> unconfirmed;
				std::list<std::string> unconfirmed_txids;
				std::string address = address::fromprikey(prikey);

				web::get_address_info(address, balance, tx, unconfirmed, 65536);

				// empty wallet cannot create a transaction
				if(tx == nullptr)
				{
					Json::Value v;
					v["error"] = "insufficient funds";
					return v;
				}

				balance = 0;

				// get confirmed balance
				for(Transaction::Input& in : tx->inputs)
				{
					if(in.address == address)
					{
						balance = in.balance;
						break;
					}
				}

				// add unconfirmed balance
				for(Transaction* source : unconfirmed)
				{
					for(Transaction::Output& out : source->outputs)
					{
						if(out.address == address)
						{
							// this shouldn't happen ever.
							// if this happens, something is very wrong. 
							if(balance + out.amount < balance)
							{
								std::cout << "integer overflow found. double spending has happened.\n";
							}

							balance += out.amount;
							unconfirmed_txids.push_back(source->get_txid());

							break;
						}
					}
				}

				// prevent spending more than allowed
				if(amount > balance)
				{
					Json::Value v;
					v["error"] = "insufficient funds";
					return v;
				}

				total_in += amount;

				tx_final.add_input(prikey, balance - amount, tx->get_txid(), unconfirmed_txids);
			}

			catch(std::exception& e)
			{
				Json::Value v;
				v["error"] = "invalid amount";
				return v;
			}
		}

		// check if the output amounts match up with the
		// input amounts
		for(Json::Value::ArrayIndex i = 0; i != len_out; i++)
		{
			try
			{
				std::string address = outputs_j[i]["address"].asString();
				uint64_t amount = std::stoul(outputs_j[i]["amount"].asString());

				if(!address::verify(address))
				{
					Json::Value v;
					v["error"] = "invalid address";
					return v;
				}

				address = address::gethash(address);
				total_out += amount;

				tx_final.add_output(address, amount, outputs_j[i]["message"].asString());
			}
			
			catch(std::exception& e)
			{
				Json::Value v;
				v["error"] = "invalid amount";
				return v;
			}
		}

		if(total_in != total_out)
		{
			Json::Value v;
			v["error"] = "total in must match total out";
			return v;
		}

		tx_final.finalize();

		web::add_transaction(&tx_final);

		return tx_final.to_json();
	}

	std::string error = generate_error("invalid method");
	write(req->sockfd, error.c_str(), error.length());

	return Json::Value();
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

		req->respond(handle_req(req, at));

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
	bool authorised = false;
	std::string http_method;
	std::string http_path;

	bool first = true;
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
				bool ignore = false;
				int at = 0;

				for(auto i = data.begin(); i != data.end(); i++)
				{
					char c = *i;

					if(c == '?')
					{
						ignore = true;
					}

					if(c == ' ' || c == '\t')
					{
						if(!last_was_break)
						{
							ignore = false;
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

						if(!ignore)
						{
							header[at] += c;
						}
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

				// content length for post requests
				if(header_key == "content-length")
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

				// authorisation can be done with cookies and headers
				else if(header_key == "auth")
				{
					if(header_value == config::http_auth)
					{
						authorised = true;
					}

					else
					{
						std::string response = generate_error("invalid auth key");
						write(sockfd, response.c_str(), response.length());

						delete this;
						return;
					}
				}

				else if(header_key == "cookie")
				{
					if(header_value.find("auth=" + config::http_auth) != std::string::npos)
					{
						authorised = true;
					}
				}
			}

			buff_upto = buffer;
		}

		else
		{
			// prevent a buffer overflow
			if(buff_upto >= buffer + sizeof(buffer))
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

			// send back a login page if the user isn't even logged in
			if(!authorised && pathv[0] != "auth")
			{
				// some html to ask a non-authenticated user to set their
				// auth cookie so they can log in via their cookie
				const std::string content = std::string()+
						"<html><head><script>"+
						"function authenticate() {"+
						"let key = document.getElementById('auth').value;"+
						"let req = new XMLHttpRequest();"+
						"req.open('POST', '/auth', true);"+
						"req.setRequestHeader('Content-Type', 'application/json');"+
						"req.send(JSON.stringify({key: key}));"+
						"req.onreadystatechange = function () {"+
						"if(this.status == 200) {"+
						"location.reload();"+
						"} else {"+
						"alert('Auth key is incorrect');"+
						"}}}</script></head><body>"+
						"<p>You are not authenticated. Please enter your Auth ID here.</p>"+
						"<input type='text' placeholder='Auth ID' id='auth'>"+
						"<button onclick='authenticate()'>Submit</button>"+
						"</body></html>";

				std::string headers = std::string()+
						"Content-Type: text/html; charset=utf-8\n" + 
						"Content-Length: "+std::to_string(content.length())+"\n";

				respond(401, "Auth", headers, content);

				delete this;
				return;
			}

			http::mtx.lock();
			http::requests.push(this);
			http::mtx.unlock();

			return;
		}
	}
}
