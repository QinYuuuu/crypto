package pce

type PCE interface {
	KeyGen() (PubK, PrivK, error)
	Encrypt(PubK, Message) (Cipher, error)
	Decrypt(PrivK, Cipher) (Message, error)
}
type Message interface{}
type PubK interface{}
type PrivK interface{}
type Cipher interface{}
