package iipa

import "go.dedis.ch/kyber/v3"

type Prover struct {
	crs *CRS
	kyber.Group
}

func (p Prover) RecursiveProve(gVec []kyber.Point, h, P kyber.Point, aVec, bVec []kyber.Scalar, n int) {
	aLen := len(aVec)
	gLen := len(gVec)
	if aLen != len(bVec) {
		return
	}
	// step 1
	if n == 1 {
		return
	}

	var proofStep []kyber.Scalar
	// step 2
	if n%2 == 1 {
		aNeg := p.Group.Scalar().Neg(aVec[aLen-1])
		bNeg := p.Group.Scalar().Neg(bVec[aLen-1])
		tmp1 := p.Group.Point().Mul(aNeg, gVec[gLen-1])
		tmp2 := p.Group.Point().Mul(p.Group.Scalar().Mul(aVec[aLen-1], bNeg), h)

		P = p.Group.Point().Add(p.Group.Point().Add(tmp1, tmp2), P)
		proofStep = append(proofStep, aNeg, bNeg)
		n = n - 1
	}

	// step 3
	n1 := n / 2
	cl := p.Group.Scalar().Zero()
	cr := p.Group.Scalar().Zero()
	var L, R kyber.Point
	for i := 0; i < n1; i++ {
		tmp1 := p.Group.Scalar().Mul(aVec[:n1][i], bVec[n1:][i])
		cl = p.Group.Scalar().Add(cl, tmp1)
		tmp2 := p.Group.Scalar().Mul(aVec[n1:][i], bVec[:n1][i])
		cr = p.Group.Scalar().Add(cr, tmp2)
		L = p.Group.Point().Mul(aVec[:n1][i], gVec[n1:][i])
		R = p.Group.Point().Mul(aVec[n1:][i], gVec[:n1][i])
	}
	L = p.Group.Point().Add(p.Group.Point().Mul(cl, h), L)
	R = p.Group.Point().Add(p.Group.Point().Mul(cr, h), R)
	//p.RecursiveProve(n1)

	// z is the challenge value
	var z kyber.Scalar
	zInv := p.Group.Scalar().Inv(z)
	// step 5, step 6
	gVec1 := make([]kyber.Point, n1)
	aVec1 := make([]kyber.Scalar, n1)
	bVec1 := make([]kyber.Scalar, n1)
	for i := 0; i < n1; i++ {
		left := p.Group.Scalar().Mul(z, bVec[:n1][i])
		right := p.Group.Scalar().Mul(zInv, bVec[n1:][i])
		bVec1[i] = p.Group.Scalar().Add(left, right)

		left1 := p.Group.Point().Mul(zInv, gVec[:n1][i])
		right1 := p.Group.Point().Mul(z, gVec[n1:][i])
		gVec1[i] = p.Group.Point().Add(left1, right1)

		left = p.Group.Scalar().Mul(z, aVec[:n1][i])
		right = p.Group.Scalar().Mul(zInv, aVec[n1:][i])
		aVec1[i] = p.Group.Scalar().Add(left, right)
	}

	z2 := p.Group.Scalar().Mul(z, z)
	z2Inv := p.Group.Scalar().Inv(z2)
	left := p.Group.Point().Mul(z2, L)
	right := p.Group.Point().Mul(z2Inv, R)
	P1 := p.Group.Point().Add(p.Group.Point().Add(P, left), right)
	p.RecursiveProve(gVec1, h, P1, aVec1, bVec1, n1)
	return
}
