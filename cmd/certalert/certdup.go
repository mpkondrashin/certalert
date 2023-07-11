package main

import (
	"crypto/x509"
	"fmt"
)

func certKey(cert *x509.Certificate) string {
	return fmt.Sprintf("%v:%v:%v:%v:%v", cert.SerialNumber, cert.Issuer, cert.Subject, cert.NotBefore, cert.NotAfter)
}

type CertDuplicatesMap map[string]struct{}

type CertDuplicates struct {
	seen CertDuplicatesMap
}

func NewCertDuplicates() *CertDuplicates {
	return &CertDuplicates{
		seen: make(CertDuplicatesMap),
	}
}

func (s *CertDuplicates) Seen(cert *x509.Certificate) bool {
	key := certKey(cert)
	_, ok := s.seen[key]
	s.seen[key] = struct{}{}
	return ok
}
