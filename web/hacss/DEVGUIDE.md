# Organization of the Codebase #

## client ##
Basic client functions, including initialization of client, sending write requests.

## communication ##
Communication functions for both replicas and clients. 

    ### receiver ###
    Receiver functions, including instantiation of all gRPC functions.
    
    ### sender ###
    Sender functions, including broadcast and send functions of []byte and string. 

## proto ##
gRPC file that implements simple network communication.


## Installation ##
1. go 

Windows: https://blog.csdn.net/u013130967/article/details/82181614

Linux (systems that have been tested so far: Ubuntu 20): sudo apt install golang-go

Go Package: https://golang.google.cn/dl/

2. protoc

**windows setup** https://blog.csdn.net/JustinSeraph/article/details/70171331?locationNum=4&fps=1
                              https://www.cnblogs.com/yinkaiblog/p/11065545.html
*if failed, download the two *.exe from https://pan.baidu.com/s/1utJDp6WJkp7jhP1lgVxqYA, password: 1234, and copy them to $GOPATH/bin

 **set up GOPATH:**
 go to the home directory of the repo

 export GOPATH=$PWD

 if you use Goland, file--setting--GO--GOPATH--Project gopath, set the HACSS folder

 **on windows machine, there are two ways to run the code:**
     1) set up GOPATH to the repository directory
     2) run a linux subsystem and run the go command (requires linux subsystem on windows)
 add #HomeDir/bin to PATH to use proto-gen-go

3. protobuf:
   https://codeload.github.com/protocolbuffers/protobuf-go/zip/master
   https://github.com/protocolbuffers/protobuf


Helper pages:
Go module: https://www.cnblogs.com/sage-blog/p/10640947.html
Golang packages: https://github.com/golang
GRPC size: https://github.com/grpc-ecosystem/grpc-gateway/issues/943

# Development #

1. write .proto file
2. compile the proto file

cd src
protoc -I proto/ proto/communication.proto --go_out=plugins=grpc:proto


3. write server and client code