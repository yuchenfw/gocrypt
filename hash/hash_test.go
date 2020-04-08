package hash

import (
	"github.com/yuchenfw/gocrypt"
	"testing"
)

type hashTest struct {
	src        []byte
	hashType   gocrypt.Hash
	key        []byte
	hashed     string
	encodeType gocrypt.Encode
}

var hashes = []hashTest{
	{
		src:        []byte("123456"),
		hashType:   gocrypt.MD5,
		hashed:     "e10adc3949ba59abbe56e057f20f883e",
		encodeType: gocrypt.HEX,
	},
	{
		src:        []byte("123456"),
		hashType:   gocrypt.SHA1,
		hashed:     "7c4a8d09ca3762af61e59520943dc26494f8941b",
		encodeType: gocrypt.HEX,
	},
	{
		src:        []byte("123456"),
		hashType:   gocrypt.SHA224,
		hashed:     "f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6",
		encodeType: gocrypt.HEX,
	},
	{
		src:        []byte("123456"),
		hashType:   gocrypt.SHA256,
		hashed:     "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
		encodeType: gocrypt.HEX,
	},
	{
		src:        []byte("123456"),
		hashType:   gocrypt.SHA384,
		hashed:     "0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454",
		encodeType: gocrypt.HEX,
	},
	{
		src:        []byte("123456"),
		hashType:   gocrypt.SHA512,
		hashed:     "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413",
		encodeType: gocrypt.HEX,
	},
	{
		src:        []byte("123456"),
		hashType:   gocrypt.SHA512_256,
		hashed:     "184b5379d5b5a7ab42d3de1d0ca1fedc1f0ffb14a7673ebd026a6369745deb72",
		encodeType: gocrypt.HEX,
	},
	{
		src:        []byte("123456"),
		hashType:   gocrypt.SHA512_224,
		hashed:     "007ca663c61310fbee4c1680a5bbe70071825079b23f092713383296",
		encodeType: gocrypt.HEX,
	},
}

func TestHash_EncodeToString(t *testing.T) {
	for _, hash := range hashes {
		h := NewHash(hash.hashType)
		dst, err := h.EncodeToString(hash.src, hash.encodeType)
		if err != nil {
			t.Fatal("error :", err)
		}
		if dst != hash.hashed {
			t.Fatalf("GetHashEncodeToString get result %s , want get %s ", dst, hash.hashed)
		}
	}
}

var hms = []hashTest{
	{
		key:        []byte("D2LOfHWU7xlf8JbR"),
		src:        []byte("123456"),
		hashType:   gocrypt.MD5,
		hashed:     "96a0f2ed8bcedd2eac0efdd685b5814c",
		encodeType: gocrypt.HEX,
	},
	{
		key:        []byte("D2LOfHWU7xlf8JbR"),
		src:        []byte("123456"),
		hashType:   gocrypt.SHA1,
		hashed:     "ea8b6afdb446a9bf06ef4fd4da61ddcd8ef1f426",
		encodeType: gocrypt.HEX,
	},
	{
		key:        []byte("D2LOfHWU7xlf8JbR"),
		src:        []byte("123456"),
		hashType:   gocrypt.SHA224,
		hashed:     "c158976429d7a36e6d6a8287afa79fde76f196d45fa65dca6cd1b4b2",
		encodeType: gocrypt.HEX,
	},
	{
		key:        []byte("D2LOfHWU7xlf8JbR"),
		src:        []byte("123456"),
		hashType:   gocrypt.SHA256,
		hashed:     "44adac09dbcab9f2e06ca7fcb706b32317705c2d18cf554bfa42f01cde6e703a",
		encodeType: gocrypt.HEX,
	},
	{
		key:        []byte("D2LOfHWU7xlf8JbR"),
		src:        []byte("123456"),
		hashType:   gocrypt.SHA384,
		hashed:     "2a761d256b7d4fb97ee0d319de01769408e0f122740ce3b1834364bfe8d530c77ce097547699da1f792743fa9d129a87",
		encodeType: gocrypt.HEX,
	},
	{
		key:        []byte("D2LOfHWU7xlf8JbR"),
		src:        []byte("123456"),
		hashType:   gocrypt.SHA512,
		hashed:     "3addd2d322e2a2c308f105061d115246f081fd50a2afc39aed79f8e2b5dabe769e6b05259d28b77ec9f4539e86182f319cb8a6b61b01511fb20f583cd61ff49c",
		encodeType: gocrypt.HEX,
	},
	{
		key:        []byte("D2LOfHWU7xlf8JbR"),
		src:        []byte("123456"),
		hashType:   gocrypt.SHA512_256,
		hashed:     "163da5721b6460f5a0d7c5a0e899ac0c45f1b2bb3e0d146bb5685aa488b667d8",
		encodeType: gocrypt.HEX,
	},
	{
		key:        []byte("D2LOfHWU7xlf8JbR"),
		src:        []byte("123456"),
		hashType:   gocrypt.SHA512_224,
		hashed:     "b4aacbc9183194363da6357082245face6258e8bcf7a8dc472ed97f2",
		encodeType: gocrypt.HEX,
	},
}

func TestHmacHash_EncodeToString(t *testing.T) {
	for _, hash := range hms {
		hh := NewHMAC(hash.hashType, hash.key)
		dst, err := hh.EncodeToString(hash.src, hash.encodeType)
		if err != nil {
			t.Fatal("error :", err)
		}
		if dst != hash.hashed {
			t.Fatalf("GetHMACHashEncodeToString get result %s , want get %s ", dst, hash.hashed)
		}
	}
}
