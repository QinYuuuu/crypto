package iipa

import "go.dedis.ch/kyber/v3"

type CRS struct {
	G []kyber.Point
	H kyber.Point
}

type Verifier struct {
	crs   *CRS
	input chan []byte
}

func NewVerifier() *Verifier {

	return &Verifier{}
}

func (v *Verifier) RecursiveVerify(n int) {
	if n == 1 {

	} else if n%2 == 1 {

	}
}
