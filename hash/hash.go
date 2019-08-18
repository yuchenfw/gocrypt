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

package hash

import (
	"crypto/hmac"
	"gocrypt"
)

type hash struct {
	hashType gocrypt.Hash
}

func NewHash(hashType gocrypt.Hash) *hash {
	return &hash{hashType}
}

//Get gets hashed bytes with defined hashType
func (h *hash) Get(src []byte) (dst []byte, err error) {
	_, dst, err = gocrypt.GetHash(src, h.hashType)
	return
}

//EncodeToString gets hashed bytes with defined hashType and then encode to string
func (h *hash) EncodeToString(src []byte, encodeType gocrypt.Encode) (dst string, err error) {
	data, err := GetHash(src, h.hashType)
	return gocrypt.EncodeToString(data, encodeType)
}

type hmacHash struct {
	hashType gocrypt.Hash
	key      []byte
}

func NewHMAC(hashType gocrypt.Hash, key []byte) *hmacHash {
	return &hmacHash{hashType, key}
}

//Get gets hmac hashed bytes with defined hashType & key
func (hh *hmacHash) Get(src []byte) (dst []byte, err error) {
	h, _ := gocrypt.GetHashFunc(hh.hashType)
	hm := hmac.New(h, hh.key)
	hm.Write(src)
	dst = hm.Sum(nil)
	return
}

//EncodeToString gets hmac hashed bytes with defined hashType & key then encode to string
func (hh *hmacHash) EncodeToString(src []byte, encodeType gocrypt.Encode) (dst string, err error) {
	data, err := GetHMACHash(src, hh.hashType, hh.key)
	return gocrypt.EncodeToString(data, encodeType)
}

//GetHash gets hashed bytes with defined hashType
func GetHash(src []byte, hashType gocrypt.Hash) (dst []byte, err error) {
	_, dst, err = gocrypt.GetHash(src, hashType)
	return
}

//GetHashEncodeToString gets hashed bytes with defined hashType and then encode to string
func GetHashEncodeToString(encodeType gocrypt.Encode, src []byte, hashType gocrypt.Hash) (dst string, err error) {
	data, err := GetHash(src, hashType)
	return gocrypt.EncodeToString(data, encodeType)
}

//GetHMACHash gets hmac hashed bytes with defined hashType & key
func GetHMACHash(src []byte, hashType gocrypt.Hash, key []byte) (dst []byte, err error) {
	h, _ := gocrypt.GetHashFunc(hashType)
	hm := hmac.New(h, key)
	hm.Write(src)
	dst = hm.Sum(nil)
	return
}

//GetHMACHashEncodeToString gets hmac hashed bytes with defined hashType & key then encode to string
func GetHMACHashEncodeToString(encodeType gocrypt.Encode, src []byte, hashType gocrypt.Hash, key []byte) (dst string, err error) {
	data, err := GetHMACHash(src, hashType, key)
	return gocrypt.EncodeToString(data, encodeType)
}
