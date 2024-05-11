package pce

import "math/rand"

type PCE interface {
	KeyGen(rand.Rand) (PubK, PrivK, error)
	Encrypt(PubK, Message) (Cipher, error)
	PCheck(PubK, Cipher, Message)
	Decrypt(PrivK, Cipher) (Message, error)
}
type Message interface{}
type PubK interface{}
type PrivK interface{}
type Cipher interface{}
