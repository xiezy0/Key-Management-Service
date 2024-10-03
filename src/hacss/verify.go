package hacss

import (
	"fmt"
	"hacss/src/cryptolib"
	"hacss/src/logging"
	"hacss/src/message"
	"log"
)

func VerifyVectorCommit_Send(m message.ReplicaMessage) bool {
	//set_i, err := DeserializeSetSend(m.Payload)
	set_i := DeserializeSetSend(m.Payload)
	//if err != nil {
	//	log.Printf("[%v] Fatal to deserialize setsend from node %v: %v", m.Instance, m.Source, err)
	//	p := fmt.Sprintf("[%v] Fatal to deserialize setsend from node %v: %v", m.Instance, m.Source, err)
	//	logging.PrintLog(verbose, logging.ErrorLog, p)
	//	return false
	//}
	fragByte, _ := set_i.RHatWitness.PolyCommit.SerializePubPoly()
	if !VerifyMerkleRoot(fragByte, set_i.RHatWitness.MerkleBranch, set_i.RHatWitness.MerkleIndex, set_i.C) {
		log.Printf("[%v] Fatal to verify merkel root for RHat from %v", m.Instance, m.Source)
		p := fmt.Sprintf("[%v] Fatal to verify merkel root from %v", m.Instance, m.Source)
		logging.PrintLog(verbose, logging.ErrorLog, p)
		return false
	}
	for k, wit := range set_i.SHatWitness {
		fragByte, _ = wit.PolyCommit.SerializePubPoly()
		if !VerifyMerkleRoot(fragByte, wit.MerkleBranch, wit.MerkleIndex, set_i.C) {
			log.Printf("[%v] Fatal to verify merkel root for SHat[%v] from  %v", m.Instance, k, m.Source)
			p := fmt.Sprintf("[%v] Fatal to verify merkel root for SHat[%v] from  %v", m.Instance, k, m.Source)
			logging.PrintLog(verbose, logging.ErrorLog, p)
			return false
		}
	}
	return true
}

func VerifyVectorCommit_Echo(m message.ReplicaMessage) bool {
	//infoMI, err := DeserializeInfoSend(m.Payload)
	infoMI := DeserializeInfoSend(m.Payload)
	//if err != nil {
	//	log.Printf("[%v] Fatal to deserialize infosend from node %v", m.Instance, m.Source)
	//	p := fmt.Sprintf("[%v] Fatal to deserialize infosend from node %v", m.Instance, m.Source)
	//	logging.PrintLog(verbose, logging.ErrorLog, p)
	//	return false
	//}
	fragByte, _ := infoMI.SWitness.PolyCommit.SerializePubPoly()
	if !VerifyMerkleRoot(fragByte, infoMI.SWitness.MerkleBranch, infoMI.SWitness.MerkleIndex, infoMI.C) {
		log.Printf("[%v] Fatal to verify merkel root for Echo from  %v", m.Instance, m.Source)
		p := fmt.Sprintf("[%v] Fatal to verify merkel root for Echo from  %v", m.Instance, m.Source)
		logging.PrintLog(verbose, logging.ErrorLog, p)
		return false
	}

	return true
}

/*
PVerify : For a given PolyCommitment PC=S_j hat, a PolyResult PR = S_j[i], and the degree "t" of the polynomial.

	Verify whether g^(PR) == Pi_(k=0)^(t)(PC[k])^(i^k)
*/
func PVerify(PC cryptolib.PubPoly, PR PolyResult) bool {
	//todo: verify using kyber lib
	return PC.Check(PR)
}

/*
VerifyDiagonal :
Given the PolyCommitment (cryptolib.PubPoly) RHat for secret polynomial with degree "p",
the PolyCommitment SHat_j for auxiliary polynomial with degree "t",
verify whether Pi_(k=0)^(t)(SHat_j[k])^(j^k) == Pi_(k=0)^(p)(RHat[k])^(j^k), i.e. for polynomial S_j(j) == R(j), and index = j
*/
func VerifyDiagonal(RHat cryptolib.PubPoly, SHat_j cryptolib.PubPoly, index int) bool {
	//todo: verify using kyber lib
	Rj := RHat.Eval(index).V
	Sj := SHat_j.Eval(index).V

	return Rj.Equal(Sj)
}
