// Copyright (c) 2020 Valentino Medimorec
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	domain          = flag.String("domain", "", "Domain for which you wish to generate SSL")
	dir             = flag.String("dir", "", "Directory where you want to generate SSL")
)

type Data struct {
	Subject pkix.Name
}

type Output struct {
	certString string
	keyString  string
	cert       *x509.Certificate
	key        *rsa.PrivateKey
}

func main() {
	flag.Parse()

	if *domain == "" {
		flag.PrintDefaults()
		log.Fatal("Missing domain name")
	}

	b := len(*domain)
	if b > 253 {
		log.Fatal("Max allowed length for a domain is 253 characters")
	}

	generateCert(*domain, *dir)
}

// Generate certificate files based on passed domain name and directory.
func generateCert(hostname string, dir string) {

	if dir != "" {
		err := os.Mkdir(dir, 0755)
		if err != nil {
			fmt.Print("Folder already exists \n")
		}

		err = os.Chdir(dir)

		if err != nil {
			log.Fatal("Could not change directory")
		}

		fmt.Printf("Using %v as folder for output \n", dir)
	}

	commonName := parseDomainName(hostname)

	fmt.Printf("Using %v as domain name \n", commonName)

	data := Data{Subject: pkix.Name{
		CommonName:         commonName,
		Organization:       []string{"Example Ltd."},
		Country:            []string{"US"},
		Province:           []string{"South Carolina"},
		Locality:           []string{"Greenville"},
		StreetAddress:      []string{"150 Cleveland Park Dr"},
		PostalCode:         []string{"29601"},
		OrganizationalUnit: []string{"Development"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte("example@" + commonName),
				},
			},
		},
	}}

	caOutput := data.createRootCert()
	caOutput.createFile("rootCA")

	certOutput := data.createServerCert(caOutput.cert, caOutput.key)
	certOutput.createFile("server")
}

// Create cert and key files locally.
func (cert Output) createFile(name string) {
	err := ioutil.WriteFile(name+".pem", []byte(cert.certString), 0755)
	if err != nil {
		fmt.Printf("Unable to write file: %v", err)
	}

	fmt.Printf("Created file: %v \n", name+".pem")

	err = ioutil.WriteFile(name+".key", []byte(cert.keyString), 0755)
	if err != nil {
		fmt.Printf("Unable to write file: %v", err)
	}

	fmt.Printf("Created file: %v \n", name+".pem")
}

// Generate root certificate.
func (data Data) createRootCert() Output {

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(generateSerial(data.Subject.CommonName)),
		Subject:               data.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create our private and public key.
	privateKey := generateKey()

	// Create the CA.
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivateKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Verify matched data.
	_, err = tls.X509KeyPair(caPEM.Bytes(), caPrivateKeyPEM.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	return Output{
		certString: caPEM.String(),
		keyString:  caPrivateKeyPEM.String(),
		cert:       ca,
		key:        privateKey,
	}
}

// Generate server certificate.
func (data Data) createServerCert(ca *x509.Certificate, caPrivateKey *rsa.PrivateKey) Output {

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(generateSerial(data.Subject.CommonName)),
		Subject:      data.Subject,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{data.Subject.CommonName, "*." + data.Subject.CommonName},
	}

	// Create our private and public key.
	privateKey := generateKey()

	// Create the CA.
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Pem encode
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	privateKeyPEM := new(bytes.Buffer)
	pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Verify matched data.
	_, err = tls.X509KeyPair(certPEM.Bytes(), privateKeyPEM.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	return Output{
		certString: certPEM.String(),
		keyString:  privateKeyPEM.String(),
		cert:       cert,
		key:        privateKey,
	}
}

// Generate private key.
func generateKey() *rsa.PrivateKey {
	// create our private and public key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	return privateKey
}

// Helper for parsing passed domain name. Fallback to .test tld.
func parseDomainName(domain string) string {
	parse, err := url.Parse(domain)
	if err != nil {
		log.Fatalf("Problem with parsing domain name")
	}

	if domain == "" {
		log.Fatalf("Missing domain name")
	}

	host := parse.Host

	if host == "" {
		if strings.Contains(domain, ".") {
			host = domain
		} else {
			// Use by default .test tld (".test" respect RFC-6761)
			host = domain + ".test"
		}

	}

	return strings.Replace(host, "www.", "", 1)
}

// Generate serial from domain name.
func generateSerial(domain string) int64 {
	runes := []rune(domain)

	var result int

	for i := 0; i < len(runes); i++ {
		result += int(runes[i])
	}

	// Random.
	ra, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		panic(err)
	}

	return int64(result*len(domain)) * ra.Int64()
}
