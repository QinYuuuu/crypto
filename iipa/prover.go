package iipa

import "go.dedis.ch/kyber/v3"

type Prover struct {
	crs *CRS
	kyber.Group
}

// RecursiveProve
func (p Prover) RecursiveProve(g_vec []kyber.Point, h, P kyber.Point, a_vec, b_vec []kyber.Scalar, u kyber.Scalar, n int) {
	aLen := len(a_vec)
	gLen := len(g_vec)
	if aLen != len(b_vec) {
		return
	}
	// step 1
	if n == 1 {
		return
	}
	var proofStep []kyber.Scalar

	// step 2
	if n%2 == 1 {
		aNeg := p.Group.Scalar().Neg(a_vec[aLen-1])
		bNeg := p.Group.Scalar().Neg(b_vec[aLen-1])
		tmp1 := p.Group.Point().Mul(aNeg, g_vec[gLen-1])
		tmp2 := p.Group.Point().Mul(bNeg, h)
		proofStep = append(proofStep, na, nb)
		n = n - 1
	}

	// step 3
	n1 := n / 2
	cl := p.Group.Scalar().Zero()
	cr := p.Group.Scalar().Zero()
	var L, R kyber.Point
	for i := 0; i < n1; i++ {
		tmp1 := p.Group.Scalar().Mul(a_vec[:n1][i], b_vec[n1:][i])
		cl = p.Group.Scalar().Add(cl, tmp1)
		tmp2 := p.Group.Scalar().Mul(a_vec[n1:][i], b_vec[:n1][i])
		cr = p.Group.Scalar().Add(cr, tmp2)
		L = p.Group.Point().Mul(a_vec[:n1][i], g_vec[n1:][i])
		R = p.Group.Point().Mul(a_vec[n1:][i], g_vec[:n1][i])

	}
	L = p.Group.Point().Add(p.Group.Point().Mul(cl, h), L)
	R = p.Group.Point().Add(p.Group.Point().Mul(cr, h), R)
	//p.RecursiveProve(n1)

	// z is the challenge value
	var z kyber.Scalar
	z_inv := p.Group.Scalar().Inv(z)
	// step 5
	g_vec1 := make([]kyber.Point, n1)
	a_vec1 := make([]kyber.Scalar, n1)
	for i := 0; i < n1; i++ {
		g_vec1[i] = p.Group.Point().Add(g_vec[:n1][i]) * g_vec[n_p:][i] * *x
	}

	// step 6
	return
}
