### The repo includes implementations of the following protocols

   - high-threshold asynchronous complete secret sharing

   - local-coin asynchronous binary agreement (ABA)

   - local-coin reproposable asynchronous binary agreement (RABA) 

   - a fully-fledged BFT consensus protocol with fast path

   - asynchronous distributed key generation (ADKG) supporting both dual thresholds and field elements as secret keys

   - various threshold cryptosystems (signatures, encryption, common coins) 



### Configuration for ADKG

configuration is under etc/conf.json

user need fill the address of replicas only


### Installation && How to run the code

#### Install dependencies

enter the directory and run the following commands

    go build src/main/server.go
    go build src/main/client.go
to generate executable files for server and client.

##### Launch the code

For all the servers, run the command below to start the servers. The [id] is configured in conf.json
server [id], for example

    server 0

Start a client with 

    client [id] [type] [para]

- [id] could be any positive integer but not serve id. 
- [type] include write(0) and write batch(1)(not used now), test hacss(2) and reconstruct secret(3) type
- [batch] is the batch size.

for example

    client 100 0 1

denotes that run a client 100 to test the whole hacss process (hacss + aba)
