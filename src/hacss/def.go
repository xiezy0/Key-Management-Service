package hacss

import (
	"encoding/json"
	"hacss/src/cryptolib"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

type ThresholdMode int

const (
	LowThreshold  ThresholdMode = 0
	HighThreshold ThresholdMode = 1
)

type Polynomial *cryptolib.PriPoly
type PolyCommitment *cryptolib.PubPoly

//type Scalar kyber.Scalar

type PolyResult *share.PriShare //  R(i)

type Witness struct {
	PolyCommit   cryptolib.PubPoly
	MerkleBranch [][]byte
	MerkleIndex  []int64
}

// SetSend use in send phase for payload in HACSS
type SetSend struct {
	C           []byte //merkle root
	G           kyber.Point
	RHatWitness Witness
	SHatWitness []Witness
	YiS         []*share.PriShare
}

type WitnessBytes struct {
	PolyCommit   []byte
	MerkleBranch [][]byte
	MerkleIndex  []int64
}

// InfoSend use in echo and ready phase for payload in HACSS. And used in reconstruct phase.
type InfoSend struct {
	C        []byte //merkle root
	G        kyber.Point
	SWitness Witness
	PResult  PolyResult
}

// InfoSend use in echo and ready phase for payload in HACSS. And used in reconstruct phase.
type InfoSendBytes struct {
	C        []byte //merkle root
	G        []byte
	SWitness []byte
	PResult  []byte
}

func (r *InfoSend) SerializeInfoSend() ([]byte, error) {
	var G_serilize []byte
	var err error
	if r.G != nil {
		G_serilize, err = cryptolib.SerilizePoint(r.G)
		if err != nil {
			return nil, err
		}
	}
	serilized_SWitness, _ := r.SWitness.SerializeWitness()
	serilized_PResult, _ := cryptolib.SerilizePriShare(r.PResult)
	info := &InfoSendBytes{
		C:        r.C,
		G:        G_serilize,
		SWitness: serilized_SWitness,
		PResult:  serilized_PResult,
	}
	json_InfoSend, err := json.Marshal(info)

	if err != nil {
		return []byte(""), err
	}
	return json_InfoSend, nil
}

func DeserializeInfoSend(Input []byte) InfoSend {
	var infoSendBytes = new(InfoSendBytes)
	var infoSend = new(InfoSend)
	err := json.Unmarshal(Input, &infoSendBytes)
	if err == nil {
		deserilized_G, _ := cryptolib.DeserializePoint(cryptolib.Suite.Point(), infoSendBytes.G)
		deserilized_SWitness := DeserilizeWitness(cryptolib.Suite.Point(), infoSendBytes.SWitness)
		deserilized_PResult := cryptolib.DeserializePriShare(cryptolib.Suite.Scalar(), infoSendBytes.PResult)
		info := &InfoSend{
			C:        infoSendBytes.C,
			G:        deserilized_G,
			SWitness: deserilized_SWitness,
			PResult:  deserilized_PResult,
		}
		return *info
	}

	return *infoSend
}

func (r *Witness) SerializeWitness() ([]byte, error) {
	serilize_polycommit, _ := r.PolyCommit.SerializePubPoly()
	witness := &WitnessBytes{
		PolyCommit:   serilize_polycommit,
		MerkleBranch: r.MerkleBranch,
		MerkleIndex:  r.MerkleIndex,
	}
	json_witness, err := json.Marshal(witness)

	if err != nil {
		return []byte(""), err
	}
	return json_witness, nil
}

func DeserilizeWitness(point kyber.Point, witnessBytesInput []byte) Witness {
	var witenessBytes = new(WitnessBytes)
	var witness = new(Witness)
	err := json.Unmarshal(witnessBytesInput, &witenessBytes)
	if err == nil {
		var PolyCommit_deserilize cryptolib.PubPoly
		PolyCommit_deserilize = cryptolib.DeserilizePubPoly(witenessBytes.PolyCommit)
		witness = &Witness{
			PolyCommit:   PolyCommit_deserilize,
			MerkleBranch: witenessBytes.MerkleBranch,
			MerkleIndex:  witenessBytes.MerkleIndex,
		}

		return *witness
	}

	return *witness
}

// SetSend use in send phase for payload in HACSS
type SetSendBytes struct {
	C           []byte //merkle root
	G           []byte
	RHatWitness []byte
	SHatWitness [][]byte
	YiS         [][]byte
}

func (r *SetSend) SerializeSetSend() ([]byte, error) {
	var G_serilize []byte
	var err error
	if r.G != nil {
		G_serilize, err = cryptolib.SerilizePoint(r.G)
		if err != nil {
			return nil, err
		}
	}
	YiS_temp := make([][]byte, 0)
	for i := 0; i < len(r.YiS); i++ {
		serilize_one_YiS, _ := cryptolib.SerilizePriShare(r.YiS[i])
		YiS_temp = append(YiS_temp, serilize_one_YiS)
	}
	serilized_RHatWitness, _ := r.RHatWitness.SerializeWitness()
	SHatWitness_temp := make([][]byte, 0)
	for i := 0; i < len(r.SHatWitness); i++ {
		serilize_one_SHatWitness, _ := r.SHatWitness[i].SerializeWitness()
		SHatWitness_temp = append(SHatWitness_temp, serilize_one_SHatWitness)
	}
	setsend := &SetSendBytes{
		C:           r.C,
		G:           G_serilize,
		RHatWitness: serilized_RHatWitness,
		SHatWitness: SHatWitness_temp,
		YiS:         YiS_temp,
	}
	json_setsend, err := json.Marshal(setsend)

	if err != nil {
		return []byte(""), err
	}
	return json_setsend, nil
}

func DeserializeSetSend(setSendBytesinput []byte) SetSend {
	var setSendBytes = new(SetSendBytes)
	var setSend = new(SetSend)
	err := json.Unmarshal(setSendBytesinput, &setSendBytes)
	if err == nil {
		deserilized_G, _ := cryptolib.DeserializePoint(cryptolib.Suite.Point(), setSendBytes.G)
		deserilized_RHatWitness := DeserilizeWitness(cryptolib.Suite.Point(), setSendBytes.RHatWitness)
		deserilized_SHatWitness := make([]Witness, len(setSendBytes.SHatWitness))
		for i := 0; i < len(setSendBytes.SHatWitness); i++ {
			deserilized_SHatWitness_tmp := DeserilizeWitness(cryptolib.Suite.Point(), setSendBytes.SHatWitness[i])
			deserilized_SHatWitness[i] = deserilized_SHatWitness_tmp
		}

		var deserilized_YiS = make([]*share.PriShare, len(setSendBytes.YiS))
		for i := 0; i < len(setSendBytes.YiS); i++ {
			deserilized_YiS_tmp := cryptolib.DeserializePriShare(cryptolib.Suite.Scalar(), setSendBytes.YiS[i])
			deserilized_YiS[i] = deserilized_YiS_tmp
		}

		setSend = &SetSend{
			C:           setSendBytes.C,
			G:           deserilized_G,
			RHatWitness: deserilized_RHatWitness,
			SHatWitness: deserilized_SHatWitness,
			YiS:         deserilized_YiS,
		}
		return *setSend
	}
	return *setSend
}
