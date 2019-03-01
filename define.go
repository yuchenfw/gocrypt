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

//Hash for crypto Hash
type Hash uint

const (
	MD5 Hash = 1 + iota
	SHA1
	SHA224
	SHA256
	SHA384
	SHA512
	SHA512_224
	SHA512_256
)

//Encode defines the type of bytes encoded to string
type Encode uint

const (
	None Encode = 1 + iota
	HEX
	Base64
)

//Secret defines the private key type
type Secret uint

const (
	PKCS1 Secret = 1 + iota
	PKCS8
)

//Crypt defines crypt types
type Crypt uint

const (
	RSA Crypt = iota + 1
)
