package main

import (
	"crypto/x509"
	"fmt"
)

type CertDuplicates map[string]struct{}

func NewCertDuplicates() CertDuplicates {
	return make(CertDuplicates)

}

func (c CertDuplicates) Seen(cert *x509.Certificate) bool {
	key := certKey(cert)
	_, ok := c[key]
	c[key] = struct{}{}
	return ok
}

func certKey(cert *x509.Certificate) string {
	return fmt.Sprintf("%v:%v:%v", cert.SerialNumber, cert.Issuer, cert.Subject)
}
