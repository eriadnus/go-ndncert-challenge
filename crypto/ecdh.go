package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
)

type ECDHState struct {
	ClientPublicKey *ecdh.PublicKey
	PublicKey       *ecdh.PublicKey
	privateKey      *ecdh.PrivateKey
}

func NewECDHState(pubKey []byte) *ECDHState {
	curveP256 := ecdh.P256()
	e := ECDHState{}
	e.PublicKey, _ = curveP256.NewPublicKey(pubKey)
	e.privateKey, _ = curveP256.GenerateKey(rand.Reader)
	e.PublicKey = e.privateKey.PublicKey()

	return &e
}

func (e *ECDHState) GetSharedSecret() []byte {
	sharedSecret, _ := e.privateKey.ECDH(e.ClientPublicKey)
	return sharedSecret
}
