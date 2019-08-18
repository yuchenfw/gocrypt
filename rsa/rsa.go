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

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"gocrypt"
)

type rsaCrypt struct {
	secretInfo RSASecret
}

type RSASecret struct {
	PublicKey          string
	PublicKeyDataType  gocrypt.Encode
	PrivateKey         string
	PrivateKeyDataType gocrypt.Encode
	PrivateKeyType     gocrypt.Secret
}

//NewRSACrypt init with the RSA secret info
func NewRSACrypt(secretInfo RSASecret) *rsaCrypt {
	return &rsaCrypt{secretInfo: secretInfo}
}

//Encrypt encrypts the given message with public key
//src the original data
//outputDataType the encode type of encrypted data ,such as Base64,HEX
func (rc *rsaCrypt) Encrypt(src string, outputDataType gocrypt.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PublicKey == "" {
		return "", fmt.Errorf("secretInfo PublicKey can't be empty")
	}
	pubKeyDecoded, err := gocrypt.DecodeString(secretInfo.PublicKey, secretInfo.PublicKeyDataType)
	if err != nil {
		return
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDecoded)
	if err != nil {
		return
	}
	var dataEncrypted []byte
	dataEncrypted, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), []byte(src))
	if err != nil {
		return
	}
	return gocrypt.EncodeToString(dataEncrypted, outputDataType)
}

//Decrypt decrypts a plaintext using private key
//src the encrypted data with public key
//srcType the encode type of encrypted data ,such as Base64,HEX
func (rc *rsaCrypt) Decrypt(src string, srcType gocrypt.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PrivateKey == "" {
		return "", fmt.Errorf("secretInfo PrivateKey can't be empty")
	}
	privateKeyDecoded, err := gocrypt.DecodeString(secretInfo.PrivateKey, secretInfo.PrivateKeyDataType)
	if err != nil {
		return
	}
	prvKey, err := gocrypt.ParsePrivateKey(privateKeyDecoded, secretInfo.PrivateKeyType)
	if err != nil {
		return
	}
	decodeData, err := gocrypt.DecodeString(src, srcType)
	if err != nil {
		return
	}
	var dataDecrypted []byte
	dataDecrypted, err = rsa.DecryptPKCS1v15(rand.Reader, prvKey, decodeData)
	if err != nil {
		return
	}
	return string(dataDecrypted), nil
}

//Sign calculates the signature of input data with the hash type & private key
//src the original unsigned data
//hashType the type of hash ,such as MD5,SHA1...
//outputDataType the encode type of sign data ,such as Base64,HEX
func (rc *rsaCrypt) Sign(src string, hashType gocrypt.Hash, outputDataType gocrypt.Encode) (dst string, err error) {
	secretInfo := rc.secretInfo
	if secretInfo.PrivateKey == "" {
		return "", fmt.Errorf("secretInfo PrivateKey can't be empty")
	}
	privateKeyDecoded, err := gocrypt.DecodeString(secretInfo.PrivateKey, secretInfo.PrivateKeyDataType)
	if err != nil {
		return
	}
	prvKey, err := gocrypt.ParsePrivateKey(privateKeyDecoded, secretInfo.PrivateKeyType)
	if err != nil {
		return
	}
	cryptoHash, hashed, err := gocrypt.GetHash([]byte(src), hashType)
	if err != nil {
		return
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, prvKey, cryptoHash, hashed)
	if err != nil {
		return
	}
	return gocrypt.EncodeToString(signature, outputDataType)
}

//VerifySign verifies input data whether match the sign data with the public key
//src the original unsigned data
//signedData the data signed with private key
//hashType the type of hash ,such as MD5,SHA1...
//signDataType the encode type of sign data ,such as Base64,HEX
func (rc *rsaCrypt) VerifySign(src string, hashType gocrypt.Hash, signedData string, signDataType gocrypt.Encode) (bool, error) {
	secretInfo := rc.secretInfo
	if secretInfo.PublicKey == "" {
		return false, fmt.Errorf("secretInfo PublicKey can't be empty")
	}
	publicKeyDecoded, err := gocrypt.DecodeString(secretInfo.PublicKey, secretInfo.PublicKeyDataType)
	if err != nil {
		return false, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyDecoded)
	if err != nil {
		return false, err
	}
	cryptoHash, hashed, err := gocrypt.GetHash([]byte(src), hashType)
	if err != nil {
		return false, err
	}
	signDecoded, err := gocrypt.DecodeString(signedData, signDataType)
	if err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), cryptoHash, hashed, signDecoded); err != nil {
		return false, err
	}
	return true, nil
}
