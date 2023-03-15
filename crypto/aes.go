package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

const nonceSizeBytes = 12
const tagSizeBytes = 16

type EncryptedMessage struct {
	/**
	Initialization Vector (IV) 12 bytes in length consisting of
	64 bits randomly generated + 32 bits counter in big endian also known as nonce.
	*/
	initializationVector [nonceSizeBytes]byte

	/**
	Authentication tag 16 bytes in length
	also known as a message authentication code (MAC).
	*/
	authenticationTag [tagSizeBytes]byte

	/**
	Encrypted payload
	*/
	encryptedPayload []byte
}

func EncryptPayload(key [tagSizeBytes]byte, plaintext []byte, requestId [8]uint8) EncryptedMessage {
	block, cipherErr := aes.NewCipher(key[:])
	if cipherErr != nil {
		panic(cipherErr.Error())
	}

	nonce := make([]byte, nonceSizeBytes)
	if _, randReadErr := io.ReadFull(rand.Reader, nonce); randReadErr != nil {
		panic(randReadErr.Error())
	}

	aesgcm, encryptErr := cipher.NewGCM(block)
	if encryptErr != nil {
		panic(encryptErr.Error())
	}

	out := aesgcm.Seal(nil, nonce, plaintext, requestId[:])
	_initializationVector := out[:nonceSizeBytes]
	encryptedPayload := out[nonceSizeBytes : nonceSizeBytes+len(plaintext)]
	_authenticationTag := out[nonceSizeBytes+len(plaintext):]

	var initializationVector [nonceSizeBytes]byte
	var authenticationTag [tagSizeBytes]byte

	copy(initializationVector[:], _initializationVector)
	copy(authenticationTag[:], _authenticationTag)

	return EncryptedMessage{
		initializationVector,
		authenticationTag,
		encryptedPayload,
	}
}

func DecryptPayload(key [16]byte, message EncryptedMessage, requestId [8]uint8) []byte {
	block, cipherErr := aes.NewCipher(key[:])
	if cipherErr != nil {
		panic(cipherErr.Error())
	}

	nonce := message.initializationVector[:]

	aesgcm, encryptErr := cipher.NewGCM(block)
	if encryptErr != nil {
		panic(encryptErr.Error())
	}

	ciphertext := append(message.encryptedPayload, message.authenticationTag[:]...)

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, requestId[:])
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}
