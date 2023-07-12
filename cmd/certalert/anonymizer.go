package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
)

var (
	ipv4NumBlock     = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	ipv4RegexPattern = ipv4NumBlock + "\\." + ipv4NumBlock + "\\." + ipv4NumBlock + "\\." + ipv4NumBlock
	IPv4RegEx        = regexp.MustCompile(ipv4RegexPattern)

	ipv6Blocks = []string{
		"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}",         // 1:2:3:4:5:6:7:8
		"([0-9a-fA-F]{1,4}:){1,7}:",                        // 1::                              1:2:3:4:5:6:7::
		"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}",        // 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
		"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}", // 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
		"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}", // 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
		"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}", // 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
		"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}", // 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
		"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})",      // 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
		":((:[0-9a-fA-F]{1,4}){1,7}|:)",                    // ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
		"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}",    // fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
		"::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])", // ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
		"([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])",    // 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
	}
	ipv6RegexPattern = strings.Join(ipv6Blocks, "|")
	IPv6RegEx        = regexp.MustCompile(ipv6RegexPattern)

	//domainNamePattern = "\\b(([a-z0-9-]{1,63}\\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,63}\\b"
	//domainNamePattern = "([A-Za-z0-9-]{1, 63}(!-)\\.)+[A-Za-z]{2, 6}"
	//domainNamePattern = "\\b(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\\.[a-zA-Z]{2,3})\\b"
	domainNamePattern = `([a-zA-Z0-9][a-zA-Z0-9.-]{0,62}\.)+[a-zA-Z]{2,}`
	DomainNameRegEx   = regexp.MustCompile(domainNamePattern)
)

func hide(v any) string {
	s := fmt.Sprintf("%v", v)
	h := hashAndTo64(s)
	if IPv4RegEx.Match([]byte(s)) {
		h = h[:6]
		return "IP4:" + h
	}
	if IPv6RegEx.Match([]byte(s)) {
		h = h[:22]
		return "IP6:" + h
	}
	if DomainNameRegEx.Match([]byte(s)) {
		h = h[:len(s)]
		return "Domain:" + h
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

func maskIPv4(input string) (result string) {
	result = IPv4RegEx.ReplaceAllStringFunc(input, func(s string) string {
		return hide(s)
	})
	result = IPv6RegEx.ReplaceAllStringFunc(result, func(s string) string {
		return hide(s)
	})
	result = DomainNameRegEx.ReplaceAllStringFunc(result, func(s string) string {
		return hide(s)
	})
	return
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
