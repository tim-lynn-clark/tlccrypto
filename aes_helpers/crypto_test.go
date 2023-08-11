package aes_helpers

import (
	"testing"
)

func TestEncryptDecryptString(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "encrypt and decrypt",
			input: "This should be properly encrypted and decrypted",
		},
	}

	key := "this_must_be_of_32_byte_length!!"

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cryptoHelper CryptoHelper

			if !cryptoHelper.IsInitialized {
				err := cryptoHelper.InitEncryption(key)
				if err != nil {
					t.Errorf("error while initializing crypto helper: %v", err.Error())
				}
			}

			//encrypting
			encryptedData, encryptErr := cryptoHelper.Encrypt(tc.input)
			if encryptErr != nil {
				t.Errorf("error while encrypting: %v", encryptErr.Error())
			}

			//decrypting
			decryptedData, decryptErr := cryptoHelper.Decrypt(encryptedData)
			if decryptErr != nil {
				t.Errorf("error while decrypting: %v", decryptErr.Error())
			}

			//value checks
			if encryptedData == tc.input {
				t.Errorf("encrypted data is not different from input data: %s vs. %s", encryptedData, tc.input)
			}
			if encryptedData == decryptedData {
				t.Errorf("encrypted data is not different from decrypted data: %s vs. %s", encryptedData, decryptedData)
			}
			if decryptedData != tc.input {
				t.Errorf("decrypted data is not equal to input data: %s vs. %s", decryptedData, tc.input)
			}
			if decryptedData != tc.input {
				t.Errorf("decrypted data is not equal to input data: %s vs. %s", decryptedData, tc.input)
			}
		})
	}
}
