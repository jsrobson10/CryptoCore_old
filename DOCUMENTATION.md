
# The official documentation for my unnamed crypto currency network

## Transactions

Transactions are proof that an exchange has happened at a certain point, at a certain time.
Transactions show the transfer of funds/tokens/NFTs, and they are the way of minting new types of 
custom tokens. 

A transaction is made up of a list of all token transfers, which all contain a list of inputs
and outputs. In a "normal" transfer, the inputs will match the outputs. However, during creation
of a new, unique token, there will be no inputs and the output values must add up to less than the
64 bit integer limit. 

- Transaction (header)
	- Transaction ID (32 bytes)
	- Transaction noise (32 bytes)
	- Token ID (32 bytes)
	- Verified transactions
		- Transaction 1 ID (64 bytes)
		- Transaction 2 ID (64 bytes)
	- Creation date (8 bytes)
	- Work done (8 bytes)
	- Number of inputs (2 bytes)
	- Number of outputs (2 bytes)
	- Inputs (list, "number of inputs" big)
		- Private Key (SIG_LEN_PUBKEY bytes)
		- Previous txid (32 bytes)
		- Balance (8 bytes)
		- Amount (8 bytes)
		- Sources size (2 bytes)
		- Sources (list, "sources size" big)
			- Source txid (32 bytes)
	- Outputs (list, "number of outputs" big)
		- Address (32 bytes)
		- Amount (8 bytes)
		- Message length (2 bytes)
		- Message ("message length" bytes)

- Transaction (whole)
	- Transaction (header)
	- Received (8 bytes)
	- Verified by transactions
		- Transaction 1 ID (32 bytes)
		- Transaction 2 ID (32 bytes)
		- Transaction 3 ID (32 bytes)
	- Inputs (list, "number of inputs" big")
		- Next txid (32 bytes)
		- Signature length (2 bytes)
		- Signature ("signature length" bytes)
	- Outputs (list, "number of outputs" big)
		- Referenced txid (32 bytes)

## NFTs

Every type of token is an NFT. NFTs, or Non Fungible Tokens, are tokens that are limited and unique.
NFTs can be created with a specific target, or they can be unowned and free to be claimed by anyone.
An NFT could be, but not limited to:

- A token or coin. This could be a stablecoin, where its value is based off another coins, or something else.
- A physical asset (like a car). One single NFT could be generated to represent the ownership of the physical asset, or more.
- Electronic art, like images, audio, video, and other files.
- Digital contracts

This is the structure of an NFT in the database:

- NFT
	- Creation date (8 bytes)
	- NFT noise (32 bytes)
	- NFT ID (32 bytes)
	- Number of targets (2 bytes)
	- Size of name (1 byte)
	- Name ("size of name" bytes)
	- Size of data (2 bytes)
	- Data ("size of data" bytes)
	- Targets (list, "number of targets" size)
		- Address (32 bytes)

## Wallets

A wallet is used to hold tokens/funds and generate new tokens. 

All wallets have:

- A seed. This generates the internal private and public keypair.
- A private key. This is used internally and is generated along with the public key with the seed. 
- A public key. This is used to verify signed messages, and used to generate the wallet address. 
- An address. This is used to send funds/tokens into, it is generated by hashing the public key. 

## The web

This is where all transactions are stored. The web uses a hash map to traverse it,
because it is unordered and it should not be assumed that the transactions are in order,
because they're not in order and they'll differ from one node to the next.  

Each transaction will be stored in transactions.bin and each hash table will be stored
in hashtable.bin.

## Hashmaps

Each bucket is 2^16 big, or holds 65536 different buckets/data. Buckets are used to make data
accessible quickly and efficiently with the use of an ID. Because each bucket holds the positions
of 65536 different buckets/data and each position is 5 bytes big (1st byte is a flag), each bucket
will hold 320 KB of data. Because there may be up to 8 buckets (very very unlikely, theres no chance
of this happening) to a transaction, the maximum theoretical size of buckets to get there will be 4 MB. 

So a transaction is made of 32 bytes, and the theoretical maximum buckets to get there is be 16.
With the transaction ID ca51059390f42b7d8d4d1c67bfe5d7073c0082c162dfe0e725dbc87b0819ac2a and a pretty
full web:

- In hashtable.bin, we jump to position 0bca51 and read the first 5 bytes
- The first byte is a 0, so the position is to the next hash table
- We jump to position 0b0593 + the position of the next table and read the first 5 bytes
- The first byte is a 0, so the position is to the next hash table
- We jump to position 0b90f4 + the position of the next table and read the first 5 bytes
- The first byte is not a 0, so we jump to the position of the transaction in transactions.bin
- We read the transaction in transactions.bin and return it

The hash map is made up of lots of smaller hash tables, where each hash table is stacked right next to
each other. 

### Transactions hashmap

Each transaction is stored in the hashmap where the transaction ID is stored first (most space efficient).
The transactions are all stored in the same file as the hashmap.

### Addresses hashmap

The addresses hashmap are more complex than the transaction hashmap, since all addresses transactions need
to be linked together but seperated from different tokens for efficiency. Every address also needs a
record of every token it owns, and access to the confirmed and unconfirmed balance of every type of token.

This is solved by hashing both just the address for a record of every token, and the address with the
token for the token specific account balance. 

- Hashed address
	- Head
		- Token 2
		- Token 1
		...

- Hashed address + token
	- Front
		- Transaction 5
		- Transaction 4
		...
	- Back
		- Transaction 1
		- Transaction 2
		...

## Core API

This is used to run commands that do certain things from outside of the core client. This is useful
for situations like having a website that processes transactions here, or having a wallet software
that uses the API. For a full list of commands, get /help on the http server. 

