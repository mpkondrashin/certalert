package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
)

const (
	numBlock     = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	regexPattern = numBlock + "\\." + numBlock + "\\." + numBlock + "\\." + numBlock
)

var IPv4RegEx = regexp.MustCompile(regexPattern)

func hide(v any) string {
	s := fmt.Sprintf("%v", v)
	h := hashAndTo64(s)
	if IPv4RegEx.Match([]byte(s)) {
		h = h[:6]
		h = "IP:" + h
	}
	return h
}

func hashAndTo64(v any) string {
	s := fmt.Sprintf("%v", v)
	hasher := sha1.New()
	hasher.Write([]byte(s))
	return to64(hasher.Sum(nil)) // fmt.Sprintf("%x", hasher.Sum(nil))
}

func to64(data []byte) string {
	var sb strings.Builder
	v := new(big.Int).SetBytes(data)
	//fmt.Printf("data = %v\n", v)
	characters := "0123456789ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz-_"

	length := big.NewInt(int64(len(characters)))
	m := new(big.Int)
	for i := 0; i < (len(data)*8+1)/6; i++ {
		v, m = v.DivMod(v, length, m)
		c := characters[m.Uint64()]
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

func maskIPv4(input string) string {
	//fmt.Printf("Mask %s\n", string(input))

	return IPv4RegEx.ReplaceAllStringFunc(input, func(s string) string {
		//fmt.Printf("IP %s\n", s)
		return "IP:" + hide(s)
	})
}

type Anonymizer struct {
	target io.Writer
}

func NewAnonymizer(target io.Writer) Anonymizer {
	return Anonymizer{
		target: target,
	}
}

func (a Anonymizer) Write(p []byte) (n int, err error) {
	// fmt.Printf("Anon %s\n", string(p))
	s := maskIPv4(string(p))
	return a.target.Write([]byte(s))
}
