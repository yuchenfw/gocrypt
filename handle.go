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
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

//getHash gets the crypto hash type & hashed data in different hash type
func getHash(data string, hashType Hash) (hash crypto.Hash, hashed []byte, err error) {
	newHash := sha1.New()
	switch hashType {
	case SHA1:
		newHash = sha1.New()
		hash = crypto.SHA1
	case SHA224:
		newHash = sha256.New224()
		hash = crypto.SHA224
	case SHA256:
		newHash = sha256.New()
		hash = crypto.SHA256
	case SHA384:
		newHash = sha512.New384()
		hash = crypto.SHA384
	case SHA512:
		newHash = sha512.New()
		hash = crypto.SHA512
	case SHA512_224:
		newHash = sha512.New512_224()
		hash = crypto.SHA512_224
	case SHA512_256:
		newHash = sha512.New512_256()
		hash = crypto.SHA512_256
	case MD5:
		newHash = md5.New()
		hash = crypto.MD5
	default:
		return hash, hashed, fmt.Errorf("unsupport hashType")
	}
	_, err = newHash.Write([]byte(data))
	if err != nil {
		return hash, hashed, err
	}
	newHash.Write([]byte(data))
	hashed = newHash.Sum(nil)
	return hash, hashed, nil
}

//decodeData decodes string data to bytes in designed encoded type
func decodeData(data string, encodedType Encode) ([]byte, error) {
	var keyDecoded []byte
	var err error
	switch encodedType {
	case None:
		keyDecoded = []byte(data)
	case HEX:
		keyDecoded, err = hex.DecodeString(data)
	case Base64:
		keyDecoded, err = base64.StdEncoding.DecodeString(data)
	default:
		return keyDecoded, fmt.Errorf("secretInfo PublicKeyDataType unsupport")
	}
	return keyDecoded, err
}

//parsePrivateKey parses private key bytes to rsa privateKey
func parsePrivateKey(privateKeyDecoded []byte, keyType Secret) (*rsa.PrivateKey, error) {
	switch keyType {
	case PKCS1:
		return x509.ParsePKCS1PrivateKey(privateKeyDecoded)
	case PKCS8:
		keyParsed, err := x509.ParsePKCS8PrivateKey(privateKeyDecoded)
		return keyParsed.(*rsa.PrivateKey), err
	default:
		return &rsa.PrivateKey{}, fmt.Errorf("secretInfo PrivateKeyDataType unsupport")
	}
}

//output encodes data to string with encode type
func output(data []byte, encodeType Encode) (string, error) {
	switch encodeType {
	case HEX:
		return hex.EncodeToString(data), nil
	case Base64:
		return base64.StdEncoding.EncodeToString(data), nil
	case None:
		return string(data), nil
	default:
		return "", fmt.Errorf("secretInfo OutputType unsupport")
	}
}
