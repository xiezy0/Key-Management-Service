package hacss

import (
	"fmt"
	"hacss/src/communication/sender"
	"hacss/src/cryptolib"
	"hacss/src/logging"
	"hacss/src/message"
	"hacss/src/quorum"
	"hacss/src/utils"
	"log"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

var id int64
var n int
var verbose bool
var epoch utils.IntValue
var g = edwards25519.NewBlakeSHA256Ed25519()

func StartHACSS(instanceid int, input []byte) {
	log.Printf("Starting HACSS %v for epoch %v\n", instanceid, epoch.Get())
	pl := fmt.Sprintf("[%v] Starting HACSS for epoch %v", instanceid, epoch.Get())
	logging.PrintLog(verbose, logging.NormalLog, pl)

	t := quorum.FSize() //define it
	p := 2 * t          //define it
	thre_p := p + 1     //define it

	//line 1 to 5
	secret := GenerateRandSecret(g, g.RandomStream())
	//log.Printf("Secret is %v", secret)
	PolyR := GenerateRandPolynomial(g, thre_p, secret, g.RandomStream())
	//log.Printf("Poly R is %v", PolyR)
	R_Poly_Commitment := GeneratePolyCommitment(PolyR)
	//log.Printf("R_Poly_Commitment is %v", R_Poly_Commitment)
	//line 5
	G := ComputeExponent(secret, g)
	//log.Printf("G is %v", G)

	//line 6 to 8
	R_Ploy_Shares := cryptolib.GenRPloyShares(PolyR, n) //compute R(1)--R(n)
	S_Share_Poly := make([]*cryptolib.PriPoly, n)
	S_Share_Poly = cryptolib.GenSSharePoly(t, n, g, g.RandomStream(), R_Ploy_Shares) //line 6 to 8, generate n poly(s) with degree t, where S(i)=R(i)

	//line 9 to 10
	S_Share_Poly_Commitment := make([]*cryptolib.PubPoly, n)
	S_Share_Poly_Commitment = cryptolib.GenSSharePolyCommitment(S_Share_Poly, n) //Generate S_Hat

	//line 11 to 12
	S_Share_Poly_Shares := make([][]*share.PriShare, 0)
	S_Share_Poly_Shares = cryptolib.GenSSharePolyShares(S_Share_Poly, n) //S_Share_Poly_Shares[i] == Si(1)--Si(n)  i.e. Y_i_S = S_Share_Poly_Shares[for j = 1 to n][i]
	var y_to_S [][]*share.PriShare
	for i := 0; i < n; i++ {
		var y_i_to_S []*share.PriShare
		for j := 0; j < n; j++ {
			y_i_to_S = append(y_i_to_S, S_Share_Poly_Shares[j][i])
		}
		y_to_S = append(y_to_S, y_i_to_S)
	}

	//line 13 to 14
	var data [][]byte
	tmp, _ := R_Poly_Commitment.SerializePubPoly()
	data = append(data, tmp)
	for _, v := range S_Share_Poly_Commitment {
		tmp, err := v.SerializePubPoly() //
		if err != nil {
			log.Printf("Commitment Serialize Err: %v", err)
			return
		}
		data = append(data, tmp)
	}
	C, branches, idxresult, suc := GenerateVectorCommitment(data)
	if !suc {
		log.Printf("Fail to get merkle branch when start HACSS for instance %v!", instanceid)
		return
	}
	//log.Printf("Vector commitment root is %v", C)
	R_hat_witness := Witness{
		PolyCommit:   R_Poly_Commitment,
		MerkleBranch: branches[0],
		MerkleIndex:  idxresult[0],
	}

	var S_hat_witness []Witness
	for i := 1; i <= n; i++ {
		tmpWitness := Witness{
			PolyCommit:   *S_Share_Poly_Commitment[i-1],
			MerkleBranch: branches[i],
			MerkleIndex:  idxresult[i],
		}
		S_hat_witness = append(S_hat_witness, tmpWitness)
	}

	//line 15 to 16
	for i := 0; i < n; i++ {
		set_i := SetSend{
			C:           C,
			G:           G,
			RHatWitness: R_hat_witness,
			SHatWitness: S_hat_witness,
			YiS:         y_to_S[i],
		}
		payload, _ := set_i.SerializeSetSend()
		msg := message.ReplicaMessage{
			Mtype:    message.HACSS_SEND,
			Instance: instanceid,
			Source:   id,
			TS:       utils.MakeTimestamp(),
			Payload:  payload,
			Epoch:    epoch.Get(),
		}
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize HACSS message")
		}

		//line 16, broadcast each element to corresponding replica.
		sender.SendToNode(msgbyte, int64(i), message.HACSS)
	}

}

func HandleHACSSMsg(inputMsg []byte) {

	tmp := message.DeserializeMessageWithSignature(inputMsg)
	t := make([]byte, len(tmp.Msg))
	copy(t, tmp.Msg)
	input := cryptolib.CBCDecrypterAES(t)
	content := message.DeserializeReplicaMessage(input)
	mtype := content.Mtype

	if !cryptolib.VerifyMAC(content.Source, tmp.Msg, tmp.Sig) {
		log.Printf("[Authentication Error] The MAC of hacss message has not been verified.")
		return
	}

	//log.Printf("handling message from %v, type %v", content.Source, mtype)
	switch mtype {
	case message.HACSS_SEND:
		HandleSend(content)
	case message.HACSS_ECHO:
		HandleEcho(content)
	case message.HACSS_READY:
		HandleReady(content)
	case message.HACSS_RECONSTRUCT:
		HandleReconstruct(content)
	default:
		log.Printf("not supported")
	}

}

// HandleReconstructMsg broadcast the commitment and share to other replicas.
func HandleReconstructMsg(inputMsg []byte) {
	rawMessage := message.DeserializeMessageWithSignature(inputMsg)
	m := message.DeserializeClientRequest(rawMessage.Msg)
	instanceID := utils.BytesToInt(m.OP)
	log.Printf("Handling reconstruct request for instance %v", instanceID)

	//line 1 to 3, Algorithm 2
	share, exi := recoverShare.Get(instanceID)
	if !exi {
		log.Printf("No instance share%v", instanceID)
		return
	}
	receivedSet, exi := receivedReq.Get(instanceID)
	if !exi {
		log.Printf("No receivedReq %v", instanceID)
		return
	}
	set_i := DeserializeSetSend(receivedSet)
	infoIM := InfoSend{
		C:        set_i.C,
		G:        set_i.G,
		SWitness: set_i.SHatWitness[int(id)],
		PResult:  share,
	}
	payload, _ := infoIM.SerializeInfoSend()
	msg := message.ReplicaMessage{
		Mtype:    message.HACSS_RECONSTRUCT,
		Instance: instanceID,
		Source:   id,
		TS:       utils.MakeTimestamp(),
		Payload:  payload,
	}
	msgbyte, err := msg.Serialize()
	if err != nil {
		log.Fatalf("failed to serialize HACSS message")
	}
	sender.MACBroadcast(msgbyte, message.HACSS)
}

func SetEpoch(e int) {
	epoch.Set(e)
}

func InitHACSS(thisid int64, numNodes int, ver bool) {
	id = thisid
	n = numNodes
	verbose = ver
	quorum.StartQuorum(n)
	//log.Printf("ini rstatus %v",rstatus.GetAll())
	rstatus.Init()
	instancestatus.Init()
	cachestatus.Init()
	receivedReq.Init()
	received.Init()

	recoverShare.Init()
	recoverSk.Init()
	recoverPk.Init()

	receivedRoot.Init()
	receivedG.Init()
	receivedFrag.Init()
	receivedReconstructFrag.Init()
	//receivedBranch.Init()

	epoch.Init()
}

func ClearRBCStatus(instanceid int) {
	rstatus.Delete(instanceid)
	instancestatus.Delete(instanceid)
	cachestatus.Delete(instanceid)
	receivedReq.Delete(instanceid)
}
