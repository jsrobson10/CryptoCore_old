
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
	volatile bool running;

	Json::Value handle_req(Request* req, std::string at);
	void process_req(Request* req);

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
			{"generatewallet", "generate a new wallet along with the private key, public key, and wallet address", "{\"seed\": seed} OR /generatewallet"},
			{"getwallet", "get a wallets other details from its private key", "{\"prikey\": prikey} OR /getwallet/<prikey>"},
			{"gettransaction", "get a given transaction by its transaction ID", "{\"txid\": txid} OR /gettransaction/<txid>"},
			{"getaddress", "get information about an address, like its balance and activity", "{\"address\": address} OR /getaddress/<address>"},
			{"gethashrate", "get current hashrate statistics and ETAs", ""},
			{"listtransactions", "find the history of every time transactions have been made to or from some addresses", "{\"addresses\": [address, ...], \"at\"?: at, \"limit\"?: limit, \"mode\"?: \"spend\" \"receive\" or \"all\"} OR /listtransactions/<address>"},
			{"send", "generate a transaction and send funds from at least 1 wallet to at least 1 address", "{\"inputs\": [{\"prikey\": prikey, \"amount\": amount}...], \"outputs\": [{\"address\", address, \"amount\": amount, \"message\": message}...]}"},
			{"getedgenodes", "get all current edge nodes", ""},
			{"getrawtransaction", "get a given raw transaction by its transaction ID", "{\"txid\": txid} OR /getrawtransaction/<txid>"},
			{"decoderawtransaction", "decode a given raw transaction", "{\"transaction\": transaction}"},
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
			continue;
		}

		Request* req = new http::Request(sock_new);
		req->handle = std::thread(&http::process_req, req);
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
		std::string seed_j = req->value["seed"].asString();
		std::string seed;

		// generate the wallet from a seed if specified
		if(seed_j.length() > 0)
		{
			seed = sig::seed_generate(seed_j);
		}

		else
		{
			seed = sig::seed_generate();
		}

		std::string prikey = sig::generate(seed);
		std::string pubkey = sig::getpubkey(prikey);
		std::string address = address::frompubkey(pubkey);

		Json::Value value;

		value["pubkey"] = to_hex(pubkey);
		value["prikey"] = address::fromhash(seed, ADDR_SECRET);
		value["address"] = address::fromhash(address, ADDR_DEPOSIT);

		return value;
	}

	else if(at == "getwallet")
	{
		std::string seed;

		if(req->pathc >= 2)
		{
			seed = req->pathv[1];
		}

		else
		{
			seed = req->value["prikey"].asString();
		}

		if(address::verify(seed) != ADDR_SECRET)
		{
			Json::Value v;
			v["error"] = "invalid prikey";

			return v;
		}

		std::string prikey = sig::generate(address::gethash(seed));
		std::string pubkey = sig::getpubkey(prikey);
		std::string address = address::frompubkey(pubkey);

		Json::Value value;

		value["prikey"] = seed;
		value["pubkey"] = to_hex(pubkey);
		value["address"] = address::fromhash(address, ADDR_DEPOSIT);

		return value;
	}

	else if(at == "gettransaction" || at == "getrawtransaction")
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

		if(address::verify(txid) != ADDR_TRANSACTION)
		{
			Json::Value v;
			v["error"] = "invalid txid";
			v["txid"] = txid;

			return v;
		}

		std::string txid_bytes = address::gethash(txid);
		Transaction* tx = web::get_transaction(txid_bytes);

		if(tx == nullptr)
		{
			Json::Value v;
			v["error"] = "transaction not found";
			v["txid"] = txid;

			return v;
		}

		Json::Value v;

		if(at == "gettransaction")
		{
			v["transaction"] = tx->to_json();
		}

		else
		{
			size_t txlen = tx->serialize_len();
			char* txc = new char[txlen];

			tx->serialize(txc);

			v["transaction"] = to_hex(txc, txlen);

			delete[] txc;
		}

		delete tx;
		return v;
	}

	else if(at == "decoderawtransaction")
	{
		std::string txc = from_hex(req->value["transaction"].asString());
		Transaction tx(txc.c_str(), txc.length(), true);

		Json::Value v;
		v["transaction"] = tx.to_json();

		return v;
	}

	else if(at == "getaddress")
	{
		/*std::string address;

		if(req->pathc >= 2)
		{
			address = req->pathv[1];
		}

		else
		{
			address = req->value["address"].asString();
		}

		if(address::verify(address) != ADDR_DEPOSIT)
		{
			Json::Value v;
			v["error"] = "invalid address";
			v["address"] = address;

			return v;
		}

		std::string address_hash = address::gethash(address);
		std::list<Transaction*> unconfirmed;
		uint64_t balance;
		Transaction* tx;
		Json::Value v;

		web::get_address_info(address_hash, balance, tx, unconfirmed, 16384);
		
		v["balance"] = std::to_string(balance);
		v["address"] = address;
		
		Json::Value& unconfirmed_j = v["unconfirmed"];

		if(unconfirmed.size() > 0)
		{
			int it = 0;

			for(Transaction* tx_u : unconfirmed)
			{
				for(Transaction::Output& out : tx_u->outputs)
				{
					if(out.address == address_hash)
					{
						unconfirmed_j[it]["amount"] = std::to_string(out.amount);
						unconfirmed_j[it]["confirms"] = tx_u->count_confirms();
						//unconfirmed_j[it]["work"] = display_unsigned_e(tx.work);
						unconfirmed_j[it]["txid"] = address::fromhash(tx_u->txid, ADDR_TRANSACTION);
						unconfirmed_j[it]["created"] = std::to_string(tx_u->created);
						unconfirmed_j[it]["received"] = std::to_string(tx_u->received);
						unconfirmed_j[it]["address"] = address;
	
						if(out.msg.length() > 0)
						{
							unconfirmed_j[it]["message"] = out.msg;
						}
						
						Json::Value& inputs_j = unconfirmed_j[it]["inputs"];
						Json::Value& outputs_j = unconfirmed_j[it]["outputs"];
						int it_i = 0, it_o = 0;

						for(Transaction::Input& in : tx_u->inputs)
						{
							inputs_j[it_i]["address"] = address::fromhash(in.address, ADDR_DEPOSIT);
							inputs_j[it_i]["amount"] = std::to_string(in.amount);
	
							it_i += 1;
						}
						
						for(Transaction::Output& out : tx_u->outputs)
						{
							outputs_j[it_o]["address"] = address::fromhash(out.address, ADDR_DEPOSIT);
							outputs_j[it_o]["amount"] = std::to_string(out.amount);
	
							if(out.msg.length() > 0)
							{
								outputs_j[it_o]["message"] = out.msg;
							}
	
							it_o += 1;
						}
						
						it += 1;

						break;
					}
				}

				delete tx_u;
			}
		}

		if(tx != nullptr)
		{
			delete tx;
		}

		return v;*/

		// TODO
	}

	else if(at == "gethashrate")
	{
		uint64_t hashrate = transaction_hashrate.load();

		Json::Value v;
		v["hashrate"] = std::to_string(hashrate);
		v["eta"] = 16777216.0 / hashrate;

		return v;
	}

	else if(at == "getedgenodes")
	{
		Json::Value v;
		int i = 0;

		for(auto& tx : web::edge_nodes)
		{
			v[i] = tx.second->to_json();
			i += 1;
		}

		return v;
	}

	else if(at == "listtransactions")
	{
		/*std::list<std::string> from;
		bool get_in, get_out;
		uint64_t at;
		int limit;

		try
		{
			limit = std::stoi(req->value["limit"].asString());
		}

		catch(std::exception& e)
		{
			limit = 64;
		}

		try
		{
			at = std::stoul(req->value["at"].asString());
		}

		catch(std::exception& e)
		{
			at = -1;
		}
		
		Json::Value& from_j = req->value["addresses"];
		std::string get_type = req->value["type"].asString();

		if(get_type == "spend")
		{
			get_in = false;
			get_out = true;
		}

		else if(get_type == "receive")
		{
			get_in = true;
			get_out = false;
		}
		
		else
		{
			get_in = true;
			get_out = true;
		}

		// get addresses
		for(int i = 0; i < from_j.size(); i++)
		{
			std::string address = from_j[i].asString();

			if(address::verify(address) != ADDR_DEPOSIT)
			{
				continue;
			}

			from.push_back(address::gethash(address));
		}

		if(req->pathc > 1)
		{
			std::string address = req->pathv[1];

			if(address::verify(address) == ADDR_DEPOSIT)
			{
				from.push_back(address::gethash(address));
			}
		}

		Json::Value v;
		Json::Value& transactions_j = v["transactions"];
		int it = 0;

		web::find_transactions(at, [&from, limit, get_in, get_out, &transactions_j, &it](Transaction& tx)
		{
			if(get_out)
			{
				for(Transaction::Input& in : tx.inputs)
				{
					for(std::string& address : from)
					{
						if(address == in.address)
						{
							transactions_j[it]["type"] = "spend";
							transactions_j[it]["amount"] = std::to_string(in.amount);
							transactions_j[it]["confirms"] = tx.count_confirms();
							//transactions_j[it]["work"] = display_unsigned_e(tx.work);
							transactions_j[it]["txid"] = address::fromhash(tx.txid, ADDR_TRANSACTION);
							transactions_j[it]["created"] = std::to_string(tx.created);
							transactions_j[it]["received"] = std::to_string(tx.received);
							transactions_j[it]["address"] = address::fromhash(address, ADDR_DEPOSIT);
	
							Json::Value& inputs_j = transactions_j[it]["inputs"];
							Json::Value& outputs_j = transactions_j[it]["outputs"];
							int it_i = 0, it_o = 0;

							for(Transaction::Input& in : tx.inputs)
							{
								inputs_j[it_i]["address"] = address::fromhash(in.address, ADDR_DEPOSIT);
								inputs_j[it_i]["amount"] = std::to_string(in.amount);
	
								it_i += 1;
							}
							
							for(Transaction::Output& out : tx.outputs)
							{
								outputs_j[it_o]["address"] = address::fromhash(out.address, ADDR_DEPOSIT);
								outputs_j[it_o]["amount"] = std::to_string(out.amount);
	
								if(out.msg.length() > 0)
								{
									outputs_j[it_o]["message"] = out.msg;
								}
	
								it_o += 1;
							}
	
							it += 1;
	
							if(it >= limit)
							{
								return false;
							}
						}
					}
				}
			}

			if(get_in)
			{
				for(Transaction::Output& out : tx.outputs)
				{
					for(std::string& address : from)
					{
						if(address == out.address)
						{
							transactions_j[it]["type"] = "receive";
							transactions_j[it]["amount"] = std::to_string(out.amount);
							transactions_j[it]["confirms"] = tx.count_confirms();
							//transactions_j[it]["work"] = display_unsigned_e(tx.work);
							transactions_j[it]["txid"] = address::fromhash(tx.txid, ADDR_TRANSACTION);
							transactions_j[it]["created"] = std::to_string(tx.created);
							transactions_j[it]["received"] = std::to_string(tx.received);
							transactions_j[it]["address"] = address::fromhash(address, ADDR_DEPOSIT);
	
							if(out.msg.length() > 0)
							{
								transactions_j[it]["message"] = out.msg;
							}
							
							Json::Value& inputs_j = transactions_j[it]["inputs"];
							Json::Value& outputs_j = transactions_j[it]["outputs"];
							int it_i = 0, it_o = 0;

							for(Transaction::Input& in : tx.inputs)
							{
								inputs_j[it_i]["address"] = address::fromhash(in.address, ADDR_DEPOSIT);
								inputs_j[it_i]["amount"] = std::to_string(in.amount);
	
								it_i += 1;
							}
							
							for(Transaction::Output& out : tx.outputs)
							{
								outputs_j[it_o]["address"] = address::fromhash(out.address, ADDR_DEPOSIT);
								outputs_j[it_o]["amount"] = std::to_string(out.amount);
	
								if(out.msg.length() > 0)
								{
									outputs_j[it_o]["message"] = out.msg;
								}
	
								it_o += 1;
							}
							
							it += 1;
	
							if(it >= limit)
							{
								return false;
							}
						}
					}
				}
			}

			return true;
		});

		v["at"] = at;

		return v;*/

		// TODO
	}

	else if(at == "send")
	{
		/*Json::Value& inputs_j = req->value["inputs"];
		Json::Value& outputs_j = req->value["outputs"];

		int len_in = inputs_j.size();
		int len_out = outputs_j.size();

		__uint128_t total_in = 0;
		__uint128_t total_out = 0;

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
				std::string prikey = inputs_j[i]["prikey"].asString();
				uint64_t amount = std::stoul(inputs_j[i]["amount"].asString());

				if(address::verify(prikey) != ADDR_SECRET)
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

				prikey = sig::generate(address::gethash(prikey));

				Transaction* tx;
				uint64_t balance_a;
				__uint128_t balance;
				std::list<Transaction*> unconfirmed;
				std::list<std::string> unconfirmed_txids;
				std::string address = address::fromprikey(prikey);
				std::string txid;

				web::get_address_info(address, balance_a, tx, unconfirmed, 16384);

				balance = 0;

				// get confirmed balance
				if(tx != nullptr)
				{
					for(Transaction::Input& in : tx->inputs)
					{
						if(in.address == address)
						{
							balance = in.balance;
							break;
						}
					}

					txid = tx->txid;

					delete tx;
				}

				// add unconfirmed balance
				for(Transaction* source : unconfirmed)
				{
					for(Transaction::Output& out : source->outputs)
					{
						if(out.address == address)
						{
							balance += out.amount;
							unconfirmed_txids.push_back(source->get_txid());

							break;
						}
					}

					delete source;
				}

				// prevent spending more than allowed
				if(amount > balance)
				{
					Json::Value v;
					v["error"] = "insufficient funds";
					return v;
				}

				total_in += amount;
				tx_final.add_input(prikey, amount, balance - amount, txid, unconfirmed_txids);
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

				if(address::verify(address) != ADDR_DEPOSIT)
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

		if(total_in > (uint64_t)-1 || total_out > (uint64_t)-1)
		{
			Json::Value v;
			v["error"] = "insufficient funds";
			return v;
		}

		tx_final.finalize();

		const char* invalid_reason = tx_final.get_errors();

		if(invalid_reason)
		{
			Json::Value v;
			v["error"] = invalid_reason;
			return v;
		}
		
		web::add_transaction(tx_final);

		return tx_final.to_json();*/

		// TODO
	}

	std::string error = generate_error("invalid method");
	write(req->sockfd, error.c_str(), error.length());

	return Json::Value();
}

void http::update()
{
	/*for(;;)
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
	}*/
}

void http::cleanup()
{
	running = false;
	::shutdown(sockfd, SHUT_RDWR);
	handle.join();
}

http::Request::Request(int fd)
{
	sockfd = fd;
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

void http::process_req(Request* req)
{
	size_t content_length = 0;
	bool authorised = false;
	std::string http_method;
	std::string http_path;

	bool first = true;
	char* buff_upto = req->buffer;
	int newlines = 0;
	char buff_c;

	uint64_t start = get_micros();

	for(;;)
	{
		read(req->sockfd, &buff_c, 1);

		// ignore these
		if(buff_c == '\r')
		{
			continue;
		}

		if(buff_c == '\n')
		{
			newlines += 1;

			size_t buff_len = (size_t)(buff_upto - req->buffer);
			char* buff_end = req->buffer + buff_len;

			if(first) // should be somethig like "METHOD /path HTTP/1.1"
			{
				std::string header[3];
				bool last_was_break = true;
				bool ignore = false;
				int at = 0;

				for(char* i = req->buffer; i < buff_end; i++)
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
					write(req->sockfd, INVALID_REQUEST.c_str(), INVALID_REQUEST.length());

					delete req;
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

				for(char* at = req->buffer; at < buff_end; at++)
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
						write(req->sockfd, INVALID_REQUEST.c_str(), INVALID_REQUEST.length());

						delete req;
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
						write(req->sockfd, response.c_str(), response.length());

						delete req;
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

			buff_upto = req->buffer;
		}

		else
		{
			// prevent a buffer overflow
			if(buff_upto >= req->buffer + sizeof(req->buffer))
			{
				write(req->sockfd, INVALID_REQUEST.c_str(), INVALID_REQUEST.length());

				delete req;
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
					write(req->sockfd, INVALID_REQUEST.c_str(), INVALID_REQUEST.length());

					delete req;
					return;
				}

				char* data = new char[content_length];

				read(req->sockfd, data, content_length);

				std::string errors;
				Json::CharReaderBuilder builder;
				auto reader = builder.newCharReader();
				
				if(!reader->parse(data, data + content_length, &req->value, &errors))
				{
					std::string response = generate_error("invalid json: " + errors);
					write(req->sockfd, response.c_str(), response.length());

					delete reader;
					delete req;
					return;
				}

				delete reader;
				delete[] data;
			}

			req->pathc = 0;
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
					req->pathc += 1;
				}
			}

			if(req->pathc == 0)
			{
				req->pathc = 1;
			}

			int path_at = 0;
			req->pathv = new std::string[req->pathc];
			buff_upto = req->buffer;

			for(auto at = http_path.begin() + 1; at < http_path.end(); at++)
			{
				char c = *at;

				// break
				if(c == '\\' || c == '/')
				{
					req->pathv[path_at++] = std::string(req->buffer, (size_t)(buff_upto - req->buffer));
					buff_upto = req->buffer;
				}

				else
				{
					*buff_upto = c;
					buff_upto += 1;
				}
			}
		
			if(buff_upto > req->buffer)
			{
				req->pathv[path_at] = std::string(req->buffer, (size_t)(buff_upto - req->buffer));
			}

			// send back a login page if the user isn't even logged in
			if(!authorised && req->pathv[0] != "auth")
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

				req->respond(401, "Auth", headers, content);

				delete req;
				return;
			}

			//http::mtx.lock();
			//http::requests.push(req);
			//http::mtx.unlock();
		
			// handle what the request is asking	
			std::string at = to_lower(req->pathv[0]);
				req->respond(handle_req(req, at));

			try
			{
			}

			catch(std::exception& e)
			{
				const std::string content = "{\"error\": \"internal error\"}\n";
				std::string headers = std::string()+
						"Content-Type: text/html; charset=utf-8\n" + 
						"Content-Length: "+std::to_string(content.length())+"\n";

				req->respond(500, "Internal", headers, content);

				std::cerr << "Exception caught: what() = " << e.what() << std::endl;

				throw e;
			}

			delete req;
			return;
		}
	}
}
