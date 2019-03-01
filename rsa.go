// Copyright 2019 gocrypt Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gocrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

type RSACrypt struct {
	secretInfo SecretInfo
}

//setSecretInfo sets the RSA secret info
func (rc *RSACrypt) setSecretInfo(secretInfo SecretInfo) {
	rc.secretInfo = secretInfo
}

//Encrypt encrypts the given message with public key
//inputData the original data
//outputDataType the encode type of encrypted data ,such as Base64,HEX
func (rc *RSACrypt) Encrypt(inputData string, outputDataType Encode) (string, error) {
	secretInfo := rc.secretInfo
	if secretInfo.PublicKey == "" {
		return "", fmt.Errorf("secretInfo PublicKey can't be empty")
	}
	pubKeyDecoded, err := decodeData(secretInfo.PublicKey, secretInfo.PublicKeyDataType)
	if err != nil {
		return "", err
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDecoded)
	if err != nil {
		return "", err
	}
	var dataEncrypted []byte
	dataEncrypted, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), []byte(inputData))
	if err != nil {
		return "", err
	}
	return output(dataEncrypted, outputDataType)
}

//Decrypt decrypts a plaintext using private key
//inputData the encrypted data with public key
//inputDataType the encode type of encrypted data ,such as Base64,HEX
func (rc *RSACrypt) Decrypt(inputData string, inputDataType Encode) (string, error) {
	secretInfo := rc.secretInfo
	if secretInfo.PrivateKey == "" {
		return "", fmt.Errorf("secretInfo PrivateKey can't be empty")
	}
	privateKeyDecoded, err := decodeData(secretInfo.PrivateKey, secretInfo.PrivateKeyDataType)
	if err != nil {
		return "", err
	}
	prvKey, err := parsePrivateKey(privateKeyDecoded, secretInfo.PrivateKeyType)
	if err != nil {
		return "", err
	}
	decodeData, err := decodeData(inputData, inputDataType)
	if err != nil {
		return "", err
	}
	var dataDencrypted []byte
	dataDencrypted, err = rsa.DecryptPKCS1v15(rand.Reader, prvKey, decodeData)
	if err != nil {
		return "", err
	}
	return string(dataDencrypted), nil
}

//Sign calculates the signature of input data with the hash type & private key
//inputData the unsigned data
//hashType the type of hash ,such as MD5,SHA1...
//outputDataType the encode type of sign data ,such as Base64,HEX
func (rc *RSACrypt) Sign(inputData string, hashType Hash, outputDataType Encode) (string, error) {
	secretInfo := rc.secretInfo
	if secretInfo.PrivateKey == "" {
		return "", fmt.Errorf("secretInfo PrivateKey can't be empty")
	}
	privateKeyDecoded, err := decodeData(secretInfo.PrivateKey, secretInfo.PrivateKeyDataType)
	if err != nil {
		return "", err
	}
	prvKey, err := parsePrivateKey(privateKeyDecoded, secretInfo.PrivateKeyType)
	if err != nil {
		return "", err
	}
	cryptoHash, hashed, err := getHash(inputData, hashType)
	if err != nil {
		return "", err
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, prvKey, cryptoHash, hashed)
	if err != nil {
		return "", err
	}
	return output(signature, outputDataType)
}

//VerifySign verifies input data whether match the sign data with the public key
//inputData the unsigned data
//signData the unsigned data signed with private key
//hashType the type of hash ,such as MD5,SHA1...
//signDataType the encode type of sign data ,such as Base64,HEX
func (rc *RSACrypt) VerifySign(inputData string, hashType Hash, signData string, signDataType Encode) (bool, error) {
	secretInfo := rc.secretInfo
	if secretInfo.PublicKey == "" {
		return false, fmt.Errorf("secretInfo PublicKey can't be empty")
	}
	publicKeyDecoded, err := decodeData(secretInfo.PublicKey, secretInfo.PublicKeyDataType)
	if err != nil {
		return false, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyDecoded)
	if err != nil {
		return false, err
	}
	cryptoHash, hashed, err := getHash(inputData, hashType)
	if err != nil {
		return false, err
	}
	signDecoded, err := decodeData(signData, signDataType)
	if err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), cryptoHash, hashed, signDecoded); err != nil {
		return false, err
	}
	return true, nil

}

func init() {
	register(RSA, &RSACrypt{})
}
