/*
   CLI for clients to submit transactions.
*/

package main

import (
	"flag"
	"hacss/src/client"
	logging "hacss/src/logging"
	pb "hacss/src/proto/proto/communication"
	"hacss/src/utils"
	"log"
	"math/rand"
	"os"
	"strconv"
	"sync"
)

const (
	//defaultMsg      = "hello"
	//defaultMsg		= "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmno1"
	defaultMsg = "abcdefg"

	helpText_Client = `
    Main function for Client. Start A client and do write or read request. 

    client-start [id] [TypeOfRequest]

    [TypeOfRequest]:
    	0 - write
		1 - write batch


    Write request:
    client-start [id] 0 [numberRequestsPerClient] [message] [frequency]

    [message]:
    	optional 

    Eamples:
    	1. client-start 100 0 1 hi 
    	//start A client with ID = 100, and send one write request with content "hi"

    	2. client-start 100 0 10 
    	//start A client with ID = 100, and send 10 write requests with default "hello" message
		
		3. client-start 100 1 10 hi 5
    	//start A client with ID = 100, and send batch requests with size 10 and default "hi" message,frequency is 5
	
    `
)

var lock sync.Mutex
var cidlist []int64
var ccidlist []int64
var freq int
var errr error

/* Initialize the client and send A write request to the system.
   Rtype WRITEBATCH is currently used for evaluation only, which will send 10 (hard-coded) batches of requests, each with numReq length
*/
func startClient(cid string, msg []byte, wtype int, numReq int) {
	log.Printf("** Client %s", cid)
	lock.Lock()
	client.StartClient(cid, true)
	lock.Unlock()

	switch client.TypeOfTx[wtype] {
	case pb.MessageType_WRITE:
		for i := 0; i < numReq; i++ {
			client.SendWriteRequest(msg)
		}
	case pb.MessageType_WRITE_BATCH:
		log.Printf("Starting A write batch, frequency: %v, size: %v,msg: %v", freq, numReq, msg)
		for i := 0; i < freq; i++ {
			client.SendBatchRequest(msg, numReq)
		}
	case pb.MessageType_RECONSTRUCT:
		client.SendReconstructRequest(numReq)
	case pb.MessageType_TEST_HACSS:

	default:
		log.Printf("Not support type of client request!")
	}
}

func CreateMsg(msgsize int) []byte {
	randbytes := make([]byte, msgsize)
	rand.Read(randbytes)
	return randbytes
}

func main() {
	//client.SetHomeDir()
	helpPtr := flag.Bool("help", false, helpText_Client)

	flag.Parse()

	id := "0"
	numReq := 1
	freq = 1
	var err error
	if len(os.Args) > 1 {
		id = os.Args[1]
	}

	if *helpPtr || len(os.Args) < 3 {
		log.Printf(helpText_Client)
		return
	}

	_, validid := utils.StringToInt64(id)
	if validid != nil {
		log.Fatal("Invalid client ID!")
	}

	logging.SetID(id)

	rtype := 0 //Write

	rtype, err = strconv.Atoi(os.Args[2])
	log.Printf("Rtype %v", rtype)
	numReq, err = strconv.Atoi(os.Args[3])
	if err != nil {
		log.Fatalf("Please enter A valid integer (number of requests or topic number)")
	}

	msg := utils.StringToBytes(defaultMsg)
	if len(os.Args) > 4 {
		//msgsize,_ := utils.StringToInt(os.Args[4])
		//msg = CreateMsg(msgsize)\
		msg = []byte(os.Args[4])
	}
	if len(os.Args) > 5 {
		freq, err = utils.StringToInt(os.Args[5])
		if err != nil {
			log.Fatalf("Please enter A valid integer (number of frequency).")
		}
	}
	log.Printf("Starting client test")

	// Write, writebatch, data service

	startClient(id, msg, rtype, numReq)

	log.Printf("Done with all client requests.")

}
