package waterbear

import (
	"fmt"
	"hacss/src/communication/sender"
	"hacss/src/cryptolib"
	"hacss/src/logging"
	"hacss/src/message"
	"hacss/src/quorum"
	"hacss/src/utils"
	"log"
)

var id int64
var iid int
var n int
var verbose bool
var members []int
var sleepTimerValue int
var mapMembers map[int]int
var cointype bool

func QueryStatus(instanceid int) bool {
	v, exist := finalstatus.Get(instanceid)
	return exist && v >= int(STATUS_DECIDED)
	//return exist && v>=int(STATUS_TERMINATE)

}

// query the decided value of instanceid in ABA
func QueryValue(instanceid int) int {
	v, exist := decidedvalue.Get(instanceid)
	if !exist {
		return -1
	}
	return v
}

func StartABAFromRoundZero(instanceid int, input int) {

	r, _ := round.Get(instanceid)

	if r > 0 {
		return
	}

	p := fmt.Sprintf("[%v] Starting ABA round %v with value %v", instanceid, r, input)
	logging.PrintLog(verbose, logging.NormalLog, p)

	HandleCachedMsg(instanceid, r)

	bvals.InsertValue(instanceid, r, input)

	msg := message.ReplicaMessage{
		Mtype:    message.ABA_BVAL,
		Instance: instanceid,
		Source:   id,
		Value:    input,
		Round:    r,
	}

	msgbyte, err := msg.Serialize()
	if err != nil {
		log.Fatalf("failed to serialize ABA message")
	}
	sender.MACBroadcast(msgbyte, message.ABA)

	if input == 1 {
		ProceedToAux(msg)
		auxvals.InsertValue(instanceid, 0, 1)
		bin_values.InsertValue(instanceid, 0, 1)
		ProceedToConf(instanceid)
	}

}

func StartABA(instanceid int, roundnum int, input int) {

	r, _ := round.Get(instanceid)

	if r != roundnum {
		//log.Printf("Round number is not equal %v, %v\n",r,roundnum)
		return
	}

	p := fmt.Sprintf("[%v] Starting ABA round %v with value %v", instanceid, r, input)
	logging.PrintLog(verbose, logging.NormalLog, p)

	HandleCachedMsg(instanceid, r)

	bvals.InsertValue(instanceid, r, input)

	msg := message.ReplicaMessage{
		Mtype:    message.ABA_BVAL,
		Instance: instanceid,
		Source:   id,
		Value:    input,
		Round:    r,
	}

	msgbyte, err := msg.Serialize()
	if err != nil {
		log.Fatalf("failed to serialize ABA message")
	}
	sender.MACBroadcast(msgbyte, message.ABA)

}

func HandleABAMsg(inputMsg []byte) {

	tmp := message.DeserializeMessageWithSignature(inputMsg)
	t := make([]byte, len(tmp.Msg))
	copy(t, tmp.Msg)
	input := cryptolib.CBCDecrypterAES(t)
	content := message.DeserializeReplicaMessage(input)
	mtype := content.Mtype

	if !cryptolib.VerifyMAC(content.Source, tmp.Msg, tmp.Sig) {
		log.Printf("[Authentication Error] The signature of aba message has not been verified.")
		return
	}

	//log.Printf("handling message from %v, type %v", source, mtype)
	switch mtype {
	case message.ABA_BVAL:
		go HandleBVAL(content)
	case message.ABA_AUX:
		go HandleAUX(content)
	case message.ABA_CONF:
		go HandleCONF(content)
	case message.ABA_FINAL:
		go HandleFINAL(content)
	default:
		log.Printf("not supported")
	}
}

func InitCoinType(ct bool) {
	cointype = ct
}

func InitABA(thisid int64, numNodes int, ver bool, mem []int, st int) {
	id = thisid
	iid, _ = utils.Int64ToInt(id)
	n = numNodes
	verbose = ver
	quorum.StartQuorum(n)
	members = mem
	sleepTimerValue = st

	round.Init()
	//initialize round numbers to 0 for all instances
	mapMembers = make(map[int]int)
	for i := 0; i < len(members); i++ {
		round.Insert(members[i], 0)
		mapMembers[members[i]] = i
	}

	InitParameters()

	instancestatus.Init()
	finalstatus.Init()
	decidedround.Init()
	decidedvalue.Init()

	astatus.Init()
	baseinstance = 1000 //hard-code to 1000 to avoid conflicts

	//coin.InitCoin(n, id, quorum.SQuorumSize(), mem, ver)
}

func InitParameters() {
	cachedMsg.Init(n)
	bvals.Init()
	bin_values.Init()
	aux_values.Init()
	conf_values.Init()
	auxvals.Init()
	auxnodes.Init()
	confvals.Init()
	confnodes.Init()
	finalvals.Init()
	finalnodes.Init()
	bvalMap.Init()
	auxMap.Init()
	confMap.Init()
}

func InitParametersForInstance(instanceid int, r int) {
	//bvals.Delete(instanceid)
	//bin_values.Delete(instanceid)
	//auxvals.Delete(instanceid)
	//auxnodes.Delete(instanceid)
	//confvals.Delete(instanceid)
	//confnodes.Delete(instanceid)
	//bvalMap.Delete(instanceid)
	astatus.Delete(instanceid)

}

func GetIndex(instanceid int) int {
	return mapMembers[instanceid]
}
