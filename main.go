package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"time"
)

type Cert struct {
	CommonName         string    `json:"cn"`
	NotAfter           time.Time `json:"not_after"`
	NotBefore          time.Time `json:"not_before"`
	DNSNames           []string  `json:"dns_names"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	IssuerCommonName   string    `json:"issuer"`
	Organizations      []string  `json:"organizations"`
	ExpireAfter        float64   `json:"expiration"`
}

func getVerifiedCertificateChains(addr string) ([][]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", addr, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	chains := conn.ConnectionState().VerifiedChains
	return chains, nil
}

func parseRemoteCertificate(addr string) (*Cert, error) {
	chains, err := getVerifiedCertificateChains(addr)
	if err != nil {
		return nil, err
	}

	var cert *Cert
	for _, chain := range chains {
		for _, crt := range chain {
			if !crt.IsCA {
				cert = &Cert{
					CommonName:         crt.Subject.CommonName,
					NotAfter:           crt.NotAfter,
					NotBefore:          crt.NotBefore,
					DNSNames:           crt.DNSNames,
					SignatureAlgorithm: crt.SignatureAlgorithm.String(),
					IssuerCommonName:   crt.Issuer.CommonName,
					Organizations:      crt.Issuer.Organization,
					ExpireAfter:        time.Until(crt.NotAfter).Seconds(),
				}
			}
		}
	}
	return cert, err
}

func parseCertificateFile(certFile string) (*Cert, error) {
	b, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	crt, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, err
	}
	return &Cert{
		CommonName:         crt.Subject.CommonName,
		NotAfter:           crt.NotAfter,
		NotBefore:          crt.NotBefore,
		DNSNames:           crt.DNSNames,
		SignatureAlgorithm: crt.SignatureAlgorithm.String(),
		IssuerCommonName:   crt.Issuer.CommonName,
		Organizations:      crt.Issuer.Organization,
		ExpireAfter:        time.Until(crt.NotAfter).Seconds(),
	}, err
}

func jsonify(cert *Cert) string {
	b, _ := json.Marshal(cert)
	return string(b)
}

func main() {

	var (
		certFile string
		addr     string
	)
	flag.StringVar(&certFile, "file", "", "The certificates.")
	flag.StringVar(&addr, "connect", "", "The remote addr. The format should be 'example.com:ssl_port'.")
	flag.Parse()

	var (
		cert *Cert
		err  error
	)

	if addr != "" {
		cert, err = parseRemoteCertificate(addr)
		if err != nil {
			fmt.Println(err)
			return
		}
	} else if certFile != "" {
		cert, err = parseCertificateFile(certFile)
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		fmt.Println("Usage:")
		flag.PrintDefaults()
		return
	}

	fmt.Println(jsonify(cert))
}
