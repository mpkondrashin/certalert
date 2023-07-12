package main

import "testing"

func TestIPv4(t *testing.T) {
	tCase := "192.168.1.1"
	match := IPv4RegEx.Match([]byte(tCase))
	if !match {
		t.Errorf("Failed on %s", tCase)
	}
}

func TestIPv6(t *testing.T) {
	tCases := []string{
		"1:2:3:4:5:6:7:8",
		"1::", "1:2:3:4:5:6:7::",
		"1::8",
		"1:2:3:4:5:6::8", "1:2:3:4:5:6::8",
		"1::7:8", "1:2:3:4:5::7:8", "1:2:3:4:5::8",
		"1::6:7:8", "1:2:3:4::6:7:8", "1:2:3:4::8",
		"1::5:6:7:8", "1:2:3::5:6:7:8", "1:2:3::8",
		"1::4:5:6:7:8", "1:2::4:5:6:7:8", "1:2::8",
		"1::3:4:5:6:7:8", "1::3:4:5:6:7:8", "1::8",
		"::2:3:4:5:6:7:8", "::2:3:4:5:6:7:8", "::8", "::",
		"fe80::7:8%eth0", "fe80::7:8%1", //     (link-local IPv6 addresses with zone index)
		"::255.255.255.255", "::ffff:255.255.255.255", "::ffff:0:255.255.255.255", //  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
		"2001:db8:3:4::192.0.2.33", "64:ff9b::192.0.2.33", // (IPv4-Embedded IPv6 Address)
	}
	for _, ipv6 := range tCases {
		t.Run(ipv6, func(t *testing.T) {
			match := IPv6RegEx.Match([]byte(ipv6))
			if !match {
				t.Errorf("Failed on %s", ipv6)
			}
		})
	}
}

func TestDomainName(t *testing.T) {
	tCases := []struct {
		expected bool
		name     string
	}{
		{true, "www.com"},
		{true, "www.site.info"},
		{false, "name"},
		{true, "0www.com"},
		{true, "abc012345678901234567890123456789012345678901234567890123456789.com"},
		{true, "Dial SMS (www.google.com)"},
	}
	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			match := DomainNameRegEx.Match([]byte(tCase.name))
			if match != tCase.expected {
				t.Errorf("%s: expected %v but got %v", tCase.name, tCase.expected, match)
			}
		})
	}
}
