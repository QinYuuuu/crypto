package iipa

import "go.dedis.ch/kyber/v3"

type Verifier struct {
	crs   *CRS
	input chan []byte
	kyber.Group
}

func NewVerifier() *Verifier {

	return &Verifier{}
}

func (v *Verifier) RecursiveVerify(gVec []kyber.Point, h, P kyber.Point, n int) bool {
	if n == 1 {
		var a, b kyber.Scalar
		left := v.Group.Point().Mul(a, gVec[0])
		right := v.Group.Point().Mul(v.Group.Scalar().Mul(a, b), h)
		PWant := v.Group.Point().Add(left, right)
		return P.Equal(PWant)
	}
	if n%2 == 1 {

	}

	x := v.Group.Scalar()
	
	return false
}
