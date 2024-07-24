package iipa

import "go.dedis.ch/kyber/v3"

type Prover struct {
	crs *CRS
	kyber.Group
}

// RecursiveProve
//
// u is the challenge value received from Verifier
func (p Prover) RecursiveProve(g_vec []kyber.Point, h, P kyber.Point, a_vec, b_vec []kyber.Scalar, u kyber.Scalar, n int) {
	aLen := len(a_vec)
	gLen := len(g_vec)
	if aLen != len(b_vec) {
		return
	}
	if n == 1 {
		return
	}
	var proofStep []kyber.Scalar
	if n%2 == 1 {
		aNeg := p.Group.Scalar().Neg(a_vec[aLen-1])
		bNeg := p.Group.Scalar().Neg(b_vec[aLen-1])
		tmp1 := p.Group.Point().Mul(aNeg, g_vec[gLen-1])
		tmp2 := p.Group.Point().Mul(bNeg, h)
		proofStep = append(proofStep, na, nb)
	}
	n1 := n / 2
	cl := p.Group.Scalar().Zero()
	cr := p.Group.Scalar().Zero()
	var L, R kyber.Point
	for i := 0; i < n1; i++ {
		tmp1 := p.Group.Scalar().Mul(a_vec[:n1][i], b_vec[n1:][i])
		cl = p.Group.Scalar().Add(cl, tmp1)
		tmp2 := p.Group.Scalar().Mul(a_vec[n1:][i], b_vec[:n1][i])
		cr = p.Group.Scalar().Add(cr, tmp2)
	}
	L = p.Group.Point().Mul(cl, u)
	R = p.Group.Point().Mul(cr, u)
	//p.RecursiveProve(n1)
	return
}
