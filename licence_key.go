package main

import (
	"crypto/des"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

var languageSignatures = map[string][2]byte{
	"de":    {0xb1, 0x60},
	"en":    {0xac, 0x88},
	"es":    {0xae, 0x10},
	"fr":    {0xfa, 0x20},
	"ja":    {0xad, 0x82},
	"ko":    {0xb5, 0x60},
	"pl":    {0xbb, 0x55},
	"pt":    {0xcd, 0x49},
	"ru":    {0xee, 0x16},
	"zh-cn": {0xce, 0x32},
	"zh-tw": {0xaa, 0x99},
}

func generateLicenseKey(version int, language string, salt [3]byte) (string, error) {
	if version < 16 || version >= 32 {
		return "", errors.New("this generator supports versions 16 through 31")
	}

	sig, ok := languageSignatures[language]
	if !ok {
		return "", fmt.Errorf("unsupported language %q", language)
	}

	data := [10]byte{
		0x68,
		0x2a,
		salt[0],
		salt[1],
		salt[2],
		sig[0],
		sig[1],
		0x65,
		byte((version - 16) << 4),
		0x32,
	}
	key := [8]byte{0xe9, 0x7f, 0xb0, 0x60, 0x77, 0x45, 0x90, 0xae}

	block, err := des.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	block.Encrypt(data[2:10], data[2:10])
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data[:])
	s = strings.NewReplacer("I", "8", "O", "9").Replace(s)

	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16], nil
}
