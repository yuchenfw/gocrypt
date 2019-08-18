package des

import (
	"gocrypt"
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
		Key:    []byte("Nff9TJFk"),
		Src:    []byte("M21qbJ"),
		Dst:    []byte{146, 90, 23, 138, 13, 179, 27, 239},
		Cipher: gocrypt.CBC,
		IV:     []byte("kFDnCKdj"),
	},
	{
		Key:    []byte("TOi0IYZB"),
		Src:    []byte("MmkRmF"),
		Dst:    []byte{101, 35, 151, 26, 233, 80, 55, 19},
		Cipher: gocrypt.ECB,
	},
	{
		Key:    []byte("nMxw0chu"),
		Src:    []byte("vtzR64ud"),
		Dst:    []byte{69, 48, 255, 140, 137, 30, 70, 28, 51, 158, 174, 13, 226, 145, 243, 237},
		Cipher: gocrypt.CBC,
		IV:     []byte("nx440tll"),
	},
	{
		Key:    []byte("o0Jqf2S8"),
		Src:    []byte("vXo0rEAj"),
		Dst:    []byte{137, 142, 59, 207, 78, 79, 151, 50, 125, 61, 12, 86, 171, 66, 163, 103},
		Cipher: gocrypt.ECB,
	},
	{
		Key:    []byte("MZXZoRq1"),
		Src:    []byte("xlMZ1G"),
		Dst:    []byte{220, 0, 128, 246, 11, 45, 183, 166},
		Cipher: gocrypt.CFB,
		IV:     []byte("cJDJmxKe"),
	},
	{
		Key:    []byte("i1whXyEz"),
		Src:    []byte("hcVDJqKg"),
		Dst:    []byte{167, 166, 231, 238, 51, 126, 124, 116, 20, 205, 216, 50, 152, 164, 140, 5},
		Cipher: gocrypt.CFB,
		IV:     []byte("nx440tll"),
	},
	{
		Key:    []byte("Suhrza8Y"),
		Src:    []byte("OC4Yyk"),
		Dst:    []byte{194, 241, 210, 3, 145, 178, 26, 7},
		Cipher: gocrypt.OFB,
		IV:     []byte("G6M9Mzcc"),
	},
	{
		Key:    []byte("b050smHT"),
		Src:    []byte("fEmHG6Tx"),
		Dst:    []byte{168, 186, 225, 240, 213, 127, 49, 112, 39, 194, 132, 31, 177, 53, 245, 214},
		Cipher: gocrypt.OFB,
		IV:     []byte("9kyVdv52"),
	},
}

func TestDESCrypt_Encrypt(t *testing.T) {
	for _, para := range paras {
		t.Log("key :", string(para.Key))
		t.Log("src :", string(para.Src))
		t.Log("IV :", string(para.IV))
		d := NewDESCrypt(para.Key)
		dst, _ := d.Encrypt(para.Src, para.Cipher, para.IV)
		t.Log("dst: ", dst)
		if string(dst) != string(para.Dst) {
			t.Fatalf("des encrypt get result :%v , want get %v ", dst, para.Dst)
		}
	}
}

func TestDESCrypt_Decrypt(t *testing.T) {
	for _, para := range paras {
		d := NewDESCrypt(para.Key)
		src, _ := d.Decrypt(para.Dst, para.Cipher, para.IV)
		t.Log("src: ", src)
		if string(src) != string(para.Src) {
			t.Fatalf("des decrypt get result :%v , want get %v ", src, para.Src)
		}
	}
}

var tps = []Para{
	{
		Key:    []byte("e6wqdj6ZdY1lsXTnemVz4G5t"),
		Src:    []byte("M21qbJ"),
		Dst:    []byte{184, 63, 77, 41, 79, 17, 234, 98},
		Cipher: gocrypt.CBC,
		IV:     []byte("kFDnCKdj"),
	},
	{
		Key:    []byte("VwnQKBtb9pnVlYDItNmZLzYH"),
		Src:    []byte("MmkRmF"),
		Dst:    []byte{196, 232, 221, 195, 99, 7, 109, 110},
		Cipher: gocrypt.ECB,
	},
	{
		Key:    []byte("TOS6KbiXvmy2Pn4cOuKbiEYM"),
		Src:    []byte("vtzR64ud"),
		Dst:    []byte{221, 163, 135, 12, 108, 3, 175, 33, 251, 184, 112, 11, 122, 12, 129, 7},
		Cipher: gocrypt.CBC,
		IV:     []byte("nx440tll"),
	},
	{
		Key:    []byte("w2jbO8bHeiRSytmDgZyO8Dtc"),
		Src:    []byte("vXo0rEAjnx440tll"),
		Dst:    []byte{122, 149, 140, 95, 247, 152, 97, 240, 102, 187, 76, 0, 71, 147, 156, 85, 230, 16, 162, 236, 129, 1, 153, 95},
		Cipher: gocrypt.ECB,
	},
	{
		Key:    []byte("dEl2tOpOaeK4jikgBixJx1c9"),
		Src:    []byte("xlMZ1G"),
		Dst:    []byte{105, 119, 18, 198, 91, 186, 186, 15},
		Cipher: gocrypt.CFB,
		IV:     []byte("cJDJmxKe"),
	},
	{
		Key:    []byte("dEl2tOpOaeK4jikgBixJx1c9"),
		Src:    []byte("hcVDJqKg"),
		Dst:    []byte{107, 30, 85, 12, 57, 38, 209, 224, 194, 16, 237, 196, 241, 253, 189, 137},
		Cipher: gocrypt.CFB,
		IV:     []byte("nx440tll"),
	},
	{
		Key:    []byte("yHZmDRTLB1XprckEyjP9ursE"),
		Src:    []byte("OC4Yyk"),
		Dst:    []byte{213, 173, 56, 201, 70, 195, 154, 254},
		Cipher: gocrypt.OFB,
		IV:     []byte("G6M9Mzcc"),
	},
	{
		Key:    []byte("yHZmDRTLB1XprckEyjP9ursE"),
		Src:    []byte("fEmHG6Tx"),
		Dst:    []byte{36, 187, 247, 150, 44, 6, 87, 235, 66, 94, 21, 216, 56, 175, 230, 47},
		Cipher: gocrypt.OFB,
		IV:     []byte("9kyVdv52"),
	},
}

func TestTripleDESCrypt_Encrypt(t *testing.T) {
	for _, para := range tps {
		t.Log("key :", string(para.Key))
		t.Log("src :", string(para.Src))
		t.Log("IV :", string(para.IV))
		d := NewTripleDESCrypt(para.Key)
		dst, err := d.Encrypt(para.Src, para.Cipher, para.IV)
		if err != nil {
			t.Log("encrypt error :", err)
		}
		t.Log("dst: ", dst)
		if string(dst) != string(para.Dst) {
			t.Fatalf("des encrypt get result :%v , want get %v ", dst, para.Dst)
		}
	}
}

func TestTripleDESCrypt_Decrypt(t *testing.T) {
	for _, para := range tps {
		t.Log("key :", string(para.Key))
		t.Log("dst :", para.Dst)
		t.Log("IV :", string(para.IV))
		d := NewTripleDESCrypt(para.Key)
		src, err := d.Decrypt(para.Dst, para.Cipher, para.IV)
		if err != nil {
			t.Log("encrypt error :", err)
		}
		t.Log("src: ", src)
		if string(src) != string(para.Src) {
			t.Fatalf("des encrypt get result :%v , want get %v ", src, para.Src)
		}
	}
}
