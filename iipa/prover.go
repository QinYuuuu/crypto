package iipa

import "go.dedis.ch/kyber/v3"

type Prover struct {
	crs *CRS
	kyber.Group
}

func (p Prover) RecursiveProve(g_vec []kyber.Point, h kyber.Point, a_vec, b_vec []kyber.Scalar, u, P kyber.Point, n int) {
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
		na := p.Group.Scalar().Neg(a_vec[aLen-1])
		nb := p.Group.Scalar().Neg(b_vec[aLen-1])
		tmp1 := p.Group.Point().Mul(na, g_vec[gLen-1])
		tmp2 := p.Group.Point().Mul(h_vec[hLen-1] * *(nb) * u * *(-na * nb)
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
