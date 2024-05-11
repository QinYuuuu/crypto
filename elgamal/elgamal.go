package elgamal

import (
	"math/big"
	"math/rand"

	"github.com/arnaucube/cryptofun/ecc"
	"github.com/arnaucube/cryptofun/elgamal"
)

type PrivK *big.Int
type PubK ecc.Point
type Message ecc.Point
type Cipher [2]ecc.Point

type EG struct {
	elgamal.EG
}

func (eg EG) KeyGen(rand *rand.Rand) (PrivK, PubK, error) {
	privK := big.NewInt(rand.Int63())
	point, err := eg.PubK(privK)
	pubK := PubK(point)
	if err != nil {
		return nil, PubK{}, err
	}
	return privK, pubK, nil
}
