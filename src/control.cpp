
#include "network.hpp"
#include "control.hpp"

Control::Control()
{
	
}

int Control::process_new_transaction(Transaction* t)
{
	if(!t->is_valid())
	{
		return -1;
	}

	std::string txid = t->get_txid();

	if(contains_id(txid))
	{
		return 0;
	}

	received_ids.push_front(txid);

	return 1;
}

void Control::broadcast_new_transaction(Transaction* t)
{
	
}

bool Control::contains_id(std::string id)
{
	for(std::string& check : received_ids)
	{
		if(check == id)
		{
			return true;
		}
	}

	return false;
}
