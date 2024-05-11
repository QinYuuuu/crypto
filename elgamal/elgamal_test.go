package elgamal

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/arnaucube/cryptofun/ecc"
	"github.com/arnaucube/cryptofun/elgamal"
	"github.com/stretchr/testify/assert"
)

func TestKeyGen(t *testing.T) {
	ec := ecc.NewEC(big.NewInt(int64(1)), big.NewInt(int64(18)), big.NewInt(int64(19)))
	g := ecc.Point{big.NewInt(int64(7)), big.NewInt(int64(11))}
	eg_raw, err := elgamal.NewEG(ec, g)
	eg := EG{eg_raw}
	assert.Nil(t, err)

	r := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	privK, pubK1, err := eg.KeyGen(r)
	assert.Nil(t, err)

	pubK2, err := eg_raw.PubK(privK)
	assert.Nil(t, err)

	if !pubK2.Equal(ecc.Point(pubK1)) {
		t.Errorf("pubK not match")
	}
}
