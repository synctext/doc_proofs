###App Integration

### Server Side Integrations

The most important thing is there are no UTXOs. Sha256(uuid) is all that is needed for name.


1. CreateBrackets


Additional Dependencies: Protobuf.js
Replaces: Sending Transactions on Bracket Transactions

For each accord, clause or event, create 1 CreateBracket transactions.
The Arguments
name = sha256(uuid)
pubKeys = publicKey.Derive(uuid). Order is irrelevant.
digests = Digests provided by client side for ILP support. Based on ILP route finding


2. SignBracket
Replaces: Spending the previously sent tx to notarize the complementation.

Arguments:
name: sha256(uuid)
sigs: From clients
preimage: from clients


3. SupercedeBracket (Mods)
Replaces: Not currently implemented
Arguments:
name: sha256(uuid)
sigs:From clients
supercedeBy:
  name:sha256(mod_uuid)
  publicKeys.publicKey.Derive(mod_uuid)
  digests: as needed for ILP

### Client Side Integrations

Dependencies. ECDSA(secp256k1) Sha256

1. Sign a bracket
  This basically replaces almost all client side bitcoin code. It requires zero roundtrips with the server or the blockchain.

 send ecda.sign(sha256(sha256(uuid)||datahash), privkey.derive(uuid)) to the server

2. Mod

 send ecda.sign(sha256("supercede:"||sha256(uuid), privkey.derive(uuid)) to the server



### DevOps Integrations

Hyperledger nodes can launched either with docker containers or bare metal. Docker file exists for them.
There is tooling for using docker networking for networking between peers.

The config file fabric.yaml

Chaincode is intended to run inside the Docker containers

port 5000 on a peer should only be accessible by the server

### BracketExplorer

The Current state of an bracket in the ledger can be done by executing the Query function.

An Event handler function needs to be written to send deserialized transactions to the Elastic Search.

It should then be possible to query by sha256(uuid) and get all transactions associated with an accord, clause or event
