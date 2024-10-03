/*
Main function for servers. Start A replica.
*/

package main

import (
	"flag"
	"hacss/src/communication/receiver"
	"log"
	"os"
)

const (
	helpText_server = `
Main function for servers. Start A replica. 
server [ReplicaID]
`
)

func main() {
	helpPtr := flag.Bool("help", false, helpText_server)
	flag.Parse()

	if *helpPtr || len(os.Args) < 2 {
		log.Printf(helpText_server)
		return
	}

	id := "0"
	if len(os.Args) > 1 {
		id = os.Args[1]
	}

	log.Printf("**Starting replica %s", id)
	receiver.StartReceiver(id, true)

}
