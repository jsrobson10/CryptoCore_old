
#include <iostream>
#include <string>

#include "hashmap.hpp"
#include "helpers.hpp"

Hashmap::Hashmap(std::string location, bool clear) : Database(location, clear)
{
	// generate the first table if this hashmap has been cleared
	if(clear)
	{
		new_table();
	}
}

Hashmap::Hashmap(std::string location) : Database(location)
{

}

uint64_t Hashmap::get(const char* digest)
{
	uint64_t at = 0;
	
	for(int i = 0; i < 16; i++)
	{
		at += get_netus(digest) * 9;
		digest += 2;

		begin(at);

		char mode;
		read(&mode, 1);

		switch(mode)
		{
			case 'T':
				at = read_netul();
				break;
			case 'V':
			{
				uint64_t pos = read_netul() + 32;
	
				begin(pos);

				return pos;
			}
			default:
				return -1;
		}
	}

	return -1;
}

bool Hashmap::remove(const char* digest)
{
	uint64_t at = 0;
	
	for(int i = 0; i < 16; i++)
	{
		at += get_netus(digest) * 9;
		digest += 2;

		begin(at);

		char mode;
		read(&mode, 1);

		switch(mode)
		{
			case 'T':
				at = read_netul();
				break;
			case 'V':
				begin(at);
				write("\0\0\0\0\0\0\0\0\0", 9);
				return true;
			default:
				return false;
		}
	}

	return false;
}

uint64_t Hashmap::create(const char* digest, size_t len)
{
	uint64_t at = 0;
	const char* digest_at = digest;

	for(int i = 0; i < 16; i++)
	{
		uint16_t digest_offset = get_netus(digest_at);
		at += digest_offset * 9;
		digest_at += 2;

		begin(at);

		char mode;
		read(&mode, 1);

		switch(mode)
		{
			case 'T':
			{
				at = read_netul();

				break;
			}
			case 'V':
			{
				// create a new table
				uint64_t item_pos = read_netul();
				uint64_t table_pos = new_table();

				// move the item thats occupied into the table
				begin(item_pos);

				char item_id[32];
				read(item_id, sizeof(item_id));

				// can't create anything if theres a conflict
				if(bytes_are_equal(item_id, digest, 32))
				{
					return -1;
				}
				
				begin(table_pos + get_netus(item_id + i * 2 + 2) * 9);
				write("V", 1);
				write_netul(item_pos);

				begin(at);
				write("T", 1);
				write_netul(table_pos);

				at = table_pos;

				break;
			}
			default:
			{
				uint64_t data_pos = get_len();

				begin(at);
				write("V", 1);
				write_netul(data_pos);

				begin(data_pos);
				write(digest, 32);
				write(nullptr, len);

				begin(data_pos + 32);
				return data_pos + 32;
			}
		}
	}

	return -1;
}

uint64_t Hashmap::new_table()
{
	end(0);

	uint64_t table_pos = get_pos();

	for(int i = 0; i < 65536; i++)
	{
		write("\0\0\0\0\0\0\0\0\0", 9);
	}

	return table_pos;
}

