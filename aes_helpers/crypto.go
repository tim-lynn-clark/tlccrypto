package aes_helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	moduleIdentifier = "tlcrypto-aes_helpers"
)

type CryptoHelper struct {
	cipherBlock   cipher.Block
	IsInitialized bool
}

func (helper *CryptoHelper) InitEncryption(secretKey string) error {
	helper.IsInitialized = false
	key := []byte(secretKey)
	if key == nil {
		return fmt.Errorf("%s: invalid secret key provided", moduleIdentifier)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%s: cipher initialization error: %v", moduleIdentifier, err.Error())
	}
	*helper = CryptoHelper{
		cipherBlock:   block,
		IsInitialized: true,
	}
	return nil
}

func (helper *CryptoHelper) Encrypt(value string) (string, error) {
	marshalledData := []byte(value)

	if !helper.IsInitialized {
		return "", fmt.Errorf("%s: CryptoHelper not initialized", moduleIdentifier)
	}

	gcm, err := cipher.NewGCM(helper.cipherBlock)
	if err != nil {
		return "", fmt.Errorf("%s: GCM cipher initialization error: %v", moduleIdentifier, err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%s: random nonce generation error: %v", moduleIdentifier, err.Error())
	}

	// Encrypt data
	encryptedByteArr := gcm.Seal(nonce, nonce, marshalledData, nil)
	return base64.URLEncoding.EncodeToString(encryptedByteArr[:]), nil
}

func (helper *CryptoHelper) Decrypt(value string) (string, error) {
	cipherBytes, _ := base64.URLEncoding.DecodeString(value)

	if !helper.IsInitialized {
		return "", fmt.Errorf("%s: CryptoHelper not initialized", moduleIdentifier)
	}

	gcm, err := cipher.NewGCM(helper.cipherBlock)
	if err != nil {
		return "", fmt.Errorf("%s: GCM cipher initialization error: %v", moduleIdentifier, err.Error())
	}

	nonce := cipherBytes[:gcm.NonceSize()]
	cipherBytes = cipherBytes[gcm.NonceSize():]

	decryptedBytes, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return "", fmt.Errorf("%s: decryption error: %v", moduleIdentifier, err.Error())
	}

	return string(decryptedBytes[:]), nil
}
