package cryptolib

import "go.dedis.ch/kyber/v3"

func SerializeScalar(scalar kyber.Scalar) ([]byte, error) {
	return scalar.MarshalBinary()
}

func DeserializeScalar(scalar kyber.Scalar, serialized_var_scalar []byte) (kyber.Scalar, error) {
	if err := scalar.UnmarshalBinary(serialized_var_scalar); err != nil {
		return nil, err
	}
	return scalar, nil
}

func SerilizePoint(point kyber.Point) ([]byte, error) {
	return point.MarshalBinary()
}

func DeserializePoint(point kyber.Point, serilized_var_point []byte) (kyber.Point, error) {
	if err := point.UnmarshalBinary(serilized_var_point); err != nil {
		return nil, err
	}
	return point, nil
}
