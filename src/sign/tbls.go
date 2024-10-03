// Package tbls implements the (t,n)-threshold Boneh-Lynn-Shacham signature
// scheme. During setup a group of n participants runs a distributed key
// generation algorithm (see kyber/share/dkg) to compute a joint public signing
// key X and one secret key share xi for each of the n signers. To compute a
// signature S on a message m, at least t ouf of n signers have to provide
// partial (BLS) signatures Si on m using their individual key shares xi which
// can then be used to recover the full (regular) BLS signature S via Lagrange
// interpolation. The signature S can be verified with the initially
// established group key X. Signatures are points on curve G1 and public keys
// are points on curve G2.
package sign

import (
	"bytes"
	"encoding/binary"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
)

// SigShare encodes a threshold BLS signature share Si = i || v where the 2-byte
// big-endian value i corresponds to the share's index and v represents the
// share's value. The signature share Si is a point on curve G1.
type SigShare []byte

// Index returns the index i of the TBLS share Si.
func (x SigShare) Index() (int, error) {
	var index uint16
	buffer := bytes.NewReader(x)
	err := binary.Read(buffer, binary.BigEndian, &index)
	if err != nil {
		return -1, err
	}
	return int(index), nil
}

// Value returns the value v of the TBLS share Si.
func (x *SigShare) Value() []byte {
	return []byte(*x)[2:]
}

// Sign creates a threshold BLS signature Si = xi * H(m) on the given message m
// using the provided secret key share xi.
func Sign(suite pairing.Suite, private *share.PriShare, m []byte) ([]byte, error) {
	buffer := new(bytes.Buffer)
	if err := binary.Write(buffer, binary.BigEndian, uint16(private.I)); err != nil {
		return nil, err
	}
	s, err := bls.Sign(suite, private.V, m)
	if err != nil {
		return nil, err
	}
	if err := binary.Write(buffer, binary.BigEndian, s); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Verify checks the given threshold BLS signature Si on the message m using
// the public key share Xi that is associated to the secret key share xi. This
// public key share Xi can be computed by evaluating the public sharing
// polynonmial at the share's index i.
func Verify(suite pairing.Suite, public *share.PubPoly, m, sig []byte) error {
	x := SigShare(sig)
	i, err := x.Index()
	if err != nil {
		return err
	}
	return bls.Verify(suite, public.Eval(i).V, m, x.Value())
}

// Recover reconstructs the full BLS signature S = x * H(m) from a threshold t
// of signature shares Si using Lagrange interpolation. The full signature S
// can be verified through the regular BLS verification routine using the
// shared public key X. The shared public key can be computed by evaluating the
// public sharing polynomial at index 0.
func Recover(suite pairing.Suite, public *share.PubPoly, m []byte, sigs [][]byte, t, n int) ([]byte, error) {
	pubShares := make([]*share.PubShare, 0)
	for _, sig := range sigs {
		x := SigShare(sig)
		i, err := x.Index()
		if err != nil {
			return nil, err
		}
		if err = bls.Verify(suite, public.Eval(i).V, m, x.Value()); err != nil {
			return nil, err
		}
		point := suite.G1().Point()
		if err := point.UnmarshalBinary(x.Value()); err != nil {
			return nil, err
		}
		pubShares = append(pubShares, &share.PubShare{I: i, V: point})
		if len(pubShares) >= t {
			break
		}
	}
	commit, err := share.RecoverCommit(suite.G1(), pubShares, t, n)
	if err != nil {
		return nil, err
	}
	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sig, nil
}
