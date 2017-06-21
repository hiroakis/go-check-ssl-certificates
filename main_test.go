package main

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseRemoteCertificate(t *testing.T) {
	cert, err := parseRemoteCertificate("google.com:443")

	assert.Nil(t, err)
	assert.Equal(t, true, strings.Contains(cert.CommonName, "google.com"), "should be true")
}

func TestParseCertificateFile(t *testing.T) {
	cert, err := parseCertificateFile("./test_certificates/my-server.crt")

	expectedNotAfter, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", "2117-05-28 07:14:47 +0000 UTC")
	expectedNotBefore, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", "2017-06-21 07:14:47 +0000 UTC")

	assert.Nil(t, err)
	assert.Equal(t, "my-server.com", cert.CommonName, "should be my-server.com")
	assert.Equal(t, expectedNotAfter, cert.NotAfter, "should be 2117-05-28 07:14:47 +0000 UTC")
	assert.Equal(t, expectedNotBefore, cert.NotBefore, "should be 2017-06-21 07:14:47 +0000 UTC")
	assert.Equal(t, "SHA1-RSA", cert.SignatureAlgorithm, "should be SHA1-RSA")
	assert.Equal(t, 0, len(cert.DNSNames), "")
	assert.Equal(t, "my-server.com", cert.IssuerCommonName, "should be my-server.com")
	assert.Equal(t, "Hiroakis", cert.Organizations[0], "should be Hiroakis")
}
