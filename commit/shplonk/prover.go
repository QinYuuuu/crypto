package shplonk

import (
	"github.com/QinYuuuu/crypto/utils"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
)

type SRS struct {
	suite pairing.Suite
	d     int
	t     int
	g1    []kyber.Point
	g2    []kyber.Point
}

type Prover struct {
	srs *SRS
}

func (p *Prover) Commit(f utils.Polynomial) kyber.Point {
	c := p.srs.g1[0]
	return c
}
