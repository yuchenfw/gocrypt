package aes

import (
	"github.com/yuchenfw/gocrypt"
	"testing"
)

type Para struct {
	Key    []byte
	Src    []byte
	Dst    []byte
	Cipher gocrypt.Cipher
	IV     []byte
}

var paras = []Para{
	{
		Key:    []byte("ZAZvBcMk2jBqcvWS"),
		Src:    []byte("BY2uzQS7C2ZYG3t"),
		Dst:    []byte{201, 165, 83, 171, 223, 136, 45, 171, 220, 150, 82, 132, 22, 176, 209, 199},
		Cipher: gocrypt.CBC,
		IV:     []byte("bgDeokmREs4lmdi4"),
	},
	{
		Key:    []byte("HnTljvdftU2eL9H1"),
		Src:    []byte("BY2uzQS7C2ZYG3"),
		Dst:    []byte{32, 110, 107, 252, 151, 23, 9, 147, 64, 98, 11, 154, 5, 217, 54, 215},
		Cipher: gocrypt.ECB,
	},
	{
		Key:    []byte("xOBgNR1fFRsColRE"),
		Src:    []byte("gbZZH6hUJFbojuoV"),
		Dst:    []byte{166, 158, 24, 77, 40, 120, 188, 108, 209, 245, 222, 213, 161, 165, 236, 246, 157, 29, 116, 215, 129, 208, 2, 174, 69, 156, 123, 47, 66, 75, 37, 33},
		Cipher: gocrypt.CBC,
		IV:     []byte("WQJoFxXfNgfagof2"),
	},
	{
		Key:    []byte("9BYW5VgnmPv6O5ft"),
		Src:    []byte("vXo0rEAjgbZZH6hUJFbojuoV"),
		Dst:    []byte{192, 141, 7, 170, 217, 96, 117, 125, 182, 252, 151, 254, 137, 243, 190, 69, 13, 211, 240, 208, 180, 218, 254, 108, 245, 97, 24, 198, 46, 50, 64, 30},
		Cipher: gocrypt.ECB,
	},
	{
		Key:    []byte("yyew5MIHd4VNdJpk"),
		Src:    []byte("miR6wvYF7RsHDn"),
		Dst:    []byte{105, 178, 174, 216, 214, 208, 167, 161, 147, 99, 25, 188, 220, 131, 175, 194},
		Cipher: gocrypt.CFB,
		IV:     []byte("FuWt1FsWvzm4cjQV"),
	},
	{
		Key:    []byte("XOQcKAUfS9UAVeUr"),
		Src:    []byte("miR6wvYF7RsHDnJT"),
		Dst:    []byte{73, 154, 80, 48, 43, 87, 57, 9, 116, 106, 238, 198, 210, 119, 237, 10, 104, 133, 9, 130, 107, 65, 115, 222, 82, 36, 255, 24, 51, 64, 49, 250},
		Cipher: gocrypt.CFB,
		IV:     []byte("PdkvSzDbgkhqD337"),
	},
	{
		Key:    []byte("kAwGwS6MidBFriv5"),
		Src:    []byte("OC4Yyk"),
		Dst:    []byte{144, 194, 23, 123, 4, 252, 226, 94, 120, 61, 7, 158, 77, 180, 166, 152},
		Cipher: gocrypt.OFB,
		IV:     []byte("PdkvSzDbgkhqD337"),
	},
	{
		Key:    []byte("mmMUf7NsH2bw6qSr"),
		Src:    []byte("NaNnMnUvVqFPOwQq"),
		Dst:    []byte{244, 103, 172, 74, 69, 235, 173, 29, 48, 124, 198, 96, 77, 186, 124, 99, 245, 71, 9, 29, 87, 137, 163, 70, 178, 9, 143, 86, 31, 48, 215, 184},
		Cipher: gocrypt.OFB,
		IV:     []byte("Ag7GdUyhKDqTZ4DB"),
	},
}

func TestAESCrypt_Encrypt(t *testing.T) {
	for _, para := range paras {
		t.Log("key :", string(para.Key))
		t.Log("src :", string(para.Src))
		t.Log("IV :", string(para.IV))
		ac := NewAESCrypt(para.Key)
		dst, _ := ac.Encrypt(para.Src, para.Cipher, para.IV)
		t.Log("dst: ", dst)
		if string(dst) != string(para.Dst) {
			t.Fatalf("des encrypt get result :%v , want get %v ", dst, para.Dst)
		}
	}
}

func TestAESCrypt_Decrypt(t *testing.T) {
	for _, para := range paras {
		ac := NewAESCrypt(para.Key)
		src, _ := ac.Decrypt(para.Dst, para.Cipher, para.IV)
		t.Log("src: ", src)
		if string(src) != string(para.Src) {
			t.Fatalf("des decrypt get result :%v , want get %v ", src, para.Src)
		}
	}
}
