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

// Package gocrypt is used to handle different crypt.
// Usage:
// import "github.com/yuchenfw/gocrypt"
//Examples or docs see http://github.com/yuchenfw/gocrypt

package gocrypt

import "fmt"

//HandleFunc defines the common func for crypt
type HandleFunc interface {
	setSecretInfo(secretInfo SecretInfo)
	Encrypt(inputData string, outputDataType Encode) (string, error)
	Decrypt(inputData string, inputDataType Encode) (string, error)
	Sign(inputData string, hashType Hash, outputDataType Encode) (string, error)
	VerifySign(inputData string, hashType Hash, signData string, signDataType Encode) (bool, error)
}

//SecretInfo private & public key info
type SecretInfo struct {
	PublicKey          string
	PublicKeyDataType  Encode
	PrivateKey         string
	PrivateKeyDataType Encode
	PrivateKeyType     Secret
}

var adapters = make(map[Crypt]HandleFunc)

//register registers different crypt type to map
func register(cryptType Crypt, handle HandleFunc) {
	if handle == nil {
		panic("config: Register adapter is nil")
	}
	if _, ok := adapters[cryptType]; ok {
		panic("can't add the same")
	}
	adapters[cryptType] = handle
}

//NewCrypt new a HandleFunc for the adapterType with the secret info
//cryptType the crypt type
//secretInfo private & public key info
func NewCrypt(cryptType Crypt, secretInfo SecretInfo) (HandleFunc, error) {
	if _, ok := adapters[cryptType]; !ok {
		return nil, fmt.Errorf("not support the adapterType")
	}
	handle := adapters[cryptType]
	handle.setSecretInfo(secretInfo)
	return handle, nil
}
