
#include "config.hpp"
#include "helpers.hpp"

#include <bdf/Bdf.hpp>
#include <openssl/rand.h>

#include <sstream>
#include <fstream>
#include <string>

std::string config::http_auth;

void config::generate()
{
	Bdf::BdfReader reader;
	Bdf::BdfObject* bdf = reader.getObject();
	Bdf::BdfNamedList* nl = bdf->getNamedList();

	char http_auth_c[32];
	RAND_bytes((uint8_t*)http_auth_c, 32);
	http_auth = to_hex(http_auth_c, 32);

	nl->get("http")->getNamedList()->get("auth")->setString(http_auth);

	std::ofstream settings_file("config.hbdf");
	reader.serializeHumanReadable(settings_file, Bdf::BdfIndent("  ", "\n"));
	settings_file.close();
}

void config::load()
{
	std::ifstream settings_file("config.hbdf");
	std::stringstream data_ss;

	char buffer[1024];

	while(settings_file.read(buffer, sizeof(buffer)))
	{
		data_ss.write(buffer, settings_file.gcount());
	}
	
	data_ss.write(buffer, settings_file.gcount());
	settings_file.close();

	try
	{
		Bdf::BdfReaderHuman reader(data_ss.str());
		Bdf::BdfObject* bdf = reader.getObject();
		Bdf::BdfNamedList* nl = bdf->getNamedList();
	
		if(nl->get("http")->getType() != Bdf::BdfTypes::NAMED_LIST)
		{
			generate();
			return;
		}
	
		Bdf::BdfNamedList* nl_http = nl->get("http")->getNamedList();
	
		if(nl_http->get("auth")->getType() != Bdf::BdfTypes::STRING)
		{
			generate();
			return;
		}
	
		http_auth = nl_http->get("auth")->getString();
	}

	catch(Bdf::BdfError& e)
	{
		generate();
	}
}

