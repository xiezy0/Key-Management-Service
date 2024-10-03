package hacss

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"hacss/src/communication/sender"
	"hacss/src/config"
	"hacss/src/logging"
	"hacss/src/message"
	"hacss/src/quorum"
	"hacss/src/utils"
	"log"
	"strconv"
	"sync"
)

type HACSSStatus int

const (
	STATUS_IDLE  HACSSStatus = 0
	STATUS_SEND  HACSSStatus = 1
	STATUS_ECHO  HACSSStatus = 2
	STATUS_READY HACSSStatus = 3
)

var rstatus utils.IntBoolMap       // broadcast status,only has value when  HACSS Deliver
var instancestatus utils.IntIntMap // status for each instance, used in HACSS
var cachestatus utils.IntIntMap    // cache status for each instance
var receivedReq utils.IntByteMap   // req is serialized setsend
var received utils.IntSet

var receivedFrag IntIntPolyresultMap
var recoverShare IntPolyresultMap

var recoverSk IntPolyresultMap
var recoverPk IntPointMap

var receivedRoot utils.IntByteMap //merkle root of all erasure coding frags of instance
var receivedG IntPointMap         //G = g^s, where s is the secret

var receivedReconstructFrag IntIntPolyresultMap

var elock sync.Mutex
var rlock sync.Mutex

// check whether the instance has been deliver in HACSS
func QueryStatus(instanceid int) bool {
	v, exist := rstatus.Get(instanceid)
	return v && exist
}

func QueryStatusCount() int {
	return rstatus.GetCount()
}

func QueryReq(instanceid int) []byte {
	v, exist := receivedReq.Get(instanceid)
	if !exist {
		return nil
	}
	return v
}

func HandleSend(m message.ReplicaMessage) {
	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	p := fmt.Sprintf("[%v] Handling send message from node %v", m.Instance, m.Source)
	logging.PrintLog(verbose, logging.NormalLog, p)

	//line 18
	if !VerifyVectorCommit_Send(m) {
		log.Printf("[%v] Fatal to verify vector commitment from  %v", m.Instance, m.Source)
		p := fmt.Sprintf("[%v] Fatal to verify vector commitment from  %v", m.Instance, m.Source)
		logging.PrintLog(verbose, logging.ErrorLog, p)
		return
	}

	//line 19
	set_i := DeserializeSetSend(m.Payload)
	for j := 1; j <= n; j++ {
		if !PVerify(set_i.SHatWitness[j-1].PolyCommit, set_i.YiS[j-1]) {
			log.Printf("[%v] Fatal PVerify for %v from  %v", m.Instance, j, m.Source)
			p := fmt.Sprintf("[%v] Fatal PVerify for %v from  %v", m.Instance, j, m.Source)
			logging.PrintLog(verbose, logging.ErrorLog, p)
			return
		}
	}

	//line 20
	for j := 0; j < n; j++ {
		if !VerifyDiagonal(set_i.RHatWitness.PolyCommit, set_i.SHatWitness[j].PolyCommit, j) {
			log.Printf("[%v] Fatal VerifyDiagonal for %v from  %v", m.Instance, j, m.Source)
			p := fmt.Sprintf("[%v] Fatal VerifyDiagonal for %v from  %v", m.Instance, j, m.Source)
			logging.PrintLog(verbose, logging.ErrorLog, p)
			return
		}
	}

	// store some metadata
	instancestatus.Insert(m.Instance, int(STATUS_SEND))
	if !received.IsTrue(m.Instance) {
		receivedReq.Insert(m.Instance, m.Payload)
		receivedRoot.Insert(m.Instance, set_i.C)
		receivedG.Insert(m.Instance, set_i.G)
		received.AddItem(m.Instance)
	}

	//line 21 to 22
	for i := 0; i < n; i++ {
		//Pi sends to Pm
		infoIM := InfoSend{
			C:        set_i.C,
			G:        set_i.G,
			SWitness: set_i.SHatWitness[i],
			PResult:  set_i.YiS[i],
		}
		payload, _ := infoIM.SerializeInfoSend()
		msg := message.ReplicaMessage{
			Mtype:    message.HACSS_ECHO,
			Instance: m.Instance,
			Source:   id,
			TS:       utils.MakeTimestamp(),
			Payload:  payload,
			Epoch:    epoch.Get(),
		}
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize HACSS message")
		}

		//line 22, broadcast each info (indeed mainly PolyResult) to corresponding replica.
		sender.SendToNode(msgbyte, int64(i), message.HACSS)
	}

	v, exist := cachestatus.Get(m.Instance)
	if exist && v >= int(STATUS_ECHO) {
		SendReady(m)
	}
	if exist && v == int(STATUS_READY) {
		Deliver(m)
	}
}

func HandleEcho(m message.ReplicaMessage) {
	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	p := fmt.Sprintf("[%v] Handling echo message from node %v", m.Instance, m.Source)
	logging.PrintLog(verbose, logging.NormalLog, p)

	//line 24
	if !VerifyVectorCommit_Echo(m) {
		log.Printf("[%v] Fatal to verify vector commitment of Echo from  %v", m.Instance, m.Source)
		p := fmt.Sprintf("[%v] Fatal to verify vector commitment of Echo from  %v", m.Instance, m.Source)
		logging.PrintLog(verbose, logging.ErrorLog, p)
		return
	}
	infoMI := DeserializeInfoSend(m.Payload)
	if !PVerify(infoMI.SWitness.PolyCommit, infoMI.PResult) {
		log.Printf("[%v] Fatal PVerify of Echo from  %v", m.Instance, m.Source)
		p := fmt.Sprintf("[%v] Fatal PVerify of Echo from  %v", m.Instance, m.Source)
		logging.PrintLog(verbose, logging.ErrorLog, p)
		return
	}

	receivedFrag.Insert(m.Instance, int(m.Source), infoMI.PResult)
	receivedG.Insert(m.Instance, infoMI.G)

	hash := utils.IntToString(m.Instance) + strconv.Itoa(int(m.Mtype))
	quorum.Add(m.Source, hash, nil, quorum.PP)
	if quorum.CheckQuorum(hash, quorum.PP) {
		//line 26
		SendReady(m)
	}
}

func SendReady(m message.ReplicaMessage) {
	elock.Lock()
	stat, _ := instancestatus.Get(m.Instance)

	if stat == int(STATUS_SEND) {
		instancestatus.Insert(m.Instance, int(STATUS_ECHO))
		elock.Unlock()
		p := fmt.Sprintf("Sending ready for instance id %v", m.Instance)
		logging.PrintLog(verbose, logging.NormalLog, p)

		msg := m
		msg.Source = id
		msg.Mtype = message.HACSS_READY

		//line 26 and 29, only carry C and G
		infoMI := DeserializeInfoSend(m.Payload)
		tmpInfo := InfoSend{
			C: infoMI.C,
			G: infoMI.G,
		}
		payload, _ := tmpInfo.SerializeInfoSend()
		msg.Payload = payload

		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize ready message")
		}
		sender.MACBroadcast(msgbyte, message.HACSS)
	} else {
		v, exist := cachestatus.Get(m.Instance)
		elock.Unlock()
		if exist && v == int(STATUS_READY) {
			instancestatus.Insert(m.Instance, int(STATUS_ECHO))
			Deliver(m)
		} else {
			cachestatus.Insert(m.Instance, int(STATUS_ECHO))
		}
	}
}

func HandleReady(m message.ReplicaMessage) {
	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	p := fmt.Sprintf("[%v] Handling ready message from node %v", m.Instance, m.Source)
	logging.PrintLog(verbose, logging.NormalLog, p)

	infoMI := DeserializeInfoSend(m.Payload)
	receivedG.Insert(m.Instance, infoMI.G)
	hash := utils.IntToString(m.Instance) + utils.BytesToString(infoMI.C) // + string(infoMI.G)
	quorum.Add(m.Source, hash, nil, quorum.CM)

	if quorum.CheckEqualSmallQuorum(hash) {
		SendReady(m)
	}

	if quorum.CheckQuorum(hash, quorum.CM) {
		Deliver(m)
	}
}

func Deliver(m message.ReplicaMessage) {
	rlock.Lock()
	stat, _ := instancestatus.Get(m.Instance)

	if stat == int(STATUS_ECHO) {
		instancestatus.Insert(m.Instance, int(STATUS_READY))
		rlock.Unlock()

		p := fmt.Sprintf("[%v] HACSS Deliver the request epoch %v, curEpoch %v", m.Instance, m.Epoch, epoch.Get())
		logging.PrintLog(verbose, logging.NormalLog, p)

		//line 32 to 33
		//now frags is a map[int]PolyResult, i.e. replicaID j corresponding poly result S_i(j) (replica i received from j)
		frags, exi := receivedFrag.Get(m.Instance)
		if !exi {
			log.Printf("[%v]Fail to get frags", m.Instance)
			log.Printf("Frags: %v", frags.GetAll())
		}
		shares := make([]*share.PriShare, n)
		for k, v := range frags.GetAll() {
			shares[k] = v
		}
		if len(shares) < quorum.SQuorumSize() {
			log.Printf("[%v]Not enough reconstruct frags", m.Instance)
			return
		}
		poly, err := InterpolatePolynomial(g, shares, quorum.SQuorumSize(), n)
		if err != nil {
			log.Printf("[%v]Fail to recover share poly:%v", m.Instance, err)
			return
		}
		myShare := ComputePolyValue(poly, int(id)+1)
		recoverShare.Insert(m.Instance, myShare)
		//log.Printf("[%v] Share is %v", m.Instance, myShare)

		rstatus.Insert(m.Instance, true)

	} else {
		rlock.Unlock()
		cachestatus.Insert(m.Instance, int(STATUS_READY))
	}
}

func HandleReconstruct(m message.ReplicaMessage) {
	p := fmt.Sprintf("[%v] Handling reconstruct message from node %v", m.Instance, m.Source)
	logging.PrintLog(verbose, logging.NormalLog, p)

	//line 6, Algorithm 2
	if !VerifyVectorCommit_Echo(m) {
		log.Printf("[%v] Fatal to verify vector commitment of Echo from  %v", m.Instance, m.Source)
		p := fmt.Sprintf("[%v] Fatal to verify vector commitment of Echo from  %v", m.Instance, m.Source)
		logging.PrintLog(verbose, logging.ErrorLog, p)
		return
	}
	infoMI := DeserializeInfoSend(m.Payload)
	if !PVerify(infoMI.SWitness.PolyCommit, infoMI.PResult) {
		log.Printf("[%v] Fatal PVerify of reconstruction from  %v", m.Instance, m.Source)
		p := fmt.Sprintf("[%v] Fatal PVerify of reconstruction from  %v", m.Instance, m.Source)
		logging.PrintLog(verbose, logging.ErrorLog, p)
		return
	}

	//store the frag received from other replicas, i.e. Pi receive Sm(m) from Pm
	receivedReconstructFrag.Insert(m.Instance, int(m.Source), infoMI.PResult)

	hash := utils.IntToString(m.Instance) + strconv.Itoa(int(m.Mtype))
	quorum.Add(m.Source, hash, nil, quorum.PP)
	if config.ThresholdMode() == int(LowThreshold) {
		if quorum.CheckSmallQuorum(hash, quorum.PP) {
			//line 8, Algorithm 2
			//get frag from receivedReconstructFrag, and recover the polynomial R
			//now frags is a map[int]PolyResult, i.e. replicaID j corresponding poly result S_j(j)
			frags, exi := receivedReconstructFrag.Get(m.Instance)
			if !exi {
				log.Printf("[%v]Fail to get reconstruct frags", m.Instance)
				return
			}

			shares := make([]*share.PriShare, n)
			for k, v := range frags.GetAll() {
				shares[k] = v
			}
			if len(shares) < quorum.SQuorumSize() {
				log.Printf("[%v]Not enough reconstruct frags", m.Instance)
				return
			}

			reSec, err := share.RecoverSecret(g, shares, quorum.SQuorumSize(), n)
			if err != nil {
				log.Printf("[%v]Fail to recover secret.", m.Instance)
			}

			log.Printf("[%v] Secret is %v", m.Instance, reSec)
		}
	} else if config.ThresholdMode() == int(HighThreshold) {
		if quorum.CheckQuorum(hash, quorum.PP) {
			//line 8, Algorithm 2
			//get frag from receivedReconstructFrag, and recover the polynomial R
			//now frags is a map[int]PolyResult, i.e. replicaID j corresponding poly result S_j(j)
			frags, exi := receivedReconstructFrag.Get(m.Instance)
			if !exi {
				log.Printf("[%v]Fail to get reconstruct frags", m.Instance)
				return
			}

			shares := make([]*share.PriShare, n)
			for k, v := range frags.GetAll() {
				shares[k] = v
			}
			if len(shares) < quorum.QuorumSize() {
				log.Printf("[%v]Not enough reconstruct frags", m.Instance)
				return
			}

			reSec, err := share.RecoverSecret(g, shares, quorum.QuorumSize(), n)
			if err != nil {
				log.Printf("[%v]Fail to recover secret.", m.Instance)
			}

			log.Printf("[%v] Secret is %v", m.Instance, reSec)
		}
	}

}

func GenerateShareKey(curEpoch int, instanceIDS []int) (*share.PriShare, kyber.Point, bool) {
	var secretKey = new(share.PriShare)
	secretKey.V = g.Scalar().Zero()

	var pubKey = g.Point().Null()

	for _, instance := range instanceIDS {
		myShare, exi := recoverShare.Get(instance)
		if !exi {
			log.Printf("[%v] Fatal get recovered share!", instance)
			p := fmt.Sprintf("[%v] Fatal get recovered share!", instance)
			logging.PrintLog(true, logging.ErrorLog, p)
			return secretKey, pubKey, false
		}
		secretKey.I = myShare.I
		secretKey.V = myShare.V.Add(secretKey.V, myShare.V)

		pub, exi := receivedG.Get(instance)
		if !exi {
			log.Printf("[%v] Fatal get G!", instance)
			p := fmt.Sprintf("[%v] Fatal get G!", instance)
			logging.PrintLog(true, logging.ErrorLog, p)
			return secretKey, pubKey, false
		}
		pubKey.Add(pubKey, pub)
	}
	recoverSk.Insert(curEpoch, secretKey)
	recoverPk.Insert(curEpoch, pubKey)
	return secretKey, pubKey, true
}

//func VerifySharingKey(cEpoch int) bool {
//	sk, exi := recoverSk.Get(cEpoch)
//	if !exi {
//		return false
//	}
//	pk, exi := recoverPk.Get(cEpoch)
//	if !exi {
//		return false
//	}
//
//}
