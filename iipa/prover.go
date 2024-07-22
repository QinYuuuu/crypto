package iipa

type Prover struct {
	crs *CRS
}

func (p Prover) RecursiveProve(n int) {
	if n == 1 {

	}
	if n%2 == 1 {

	}
	n1 := n / 2
	p.RecursiveProve(n1)
	return
}
