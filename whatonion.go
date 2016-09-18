// whatonion.go - file(1) for onion keyfiles.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of whatonion, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package main

import(
	"fmt"
	"flag"
	"log"
	"io/ioutil"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/nogoegst/onionutil"
)
func loadRSAPrivateKeyFile(filename string) (*rsa.PrivateKey, error) {
	fileContent, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(fileContent)
	// XXX: not so readable
	if len(rest) == len(fileContent) {
		return nil, fmt.Errorf("No vailid PEM blocks found")
	}

	if block.Type == "RSA PRIVATE KEY" {
		sk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return sk, err
	} else {
		return nil, fmt.Errorf("There is no RSA PRIVATE KEY header")
	}
}

func PubkeyFromKeyfile(filename string) (pk *rsa.PublicKey, err error) {
	sk, err := loadRSAPrivateKeyFile(filename)
	if err != nil {
		return nil, err
	} else {
		return sk.Public().(*rsa.PublicKey), nil
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		log.Fatalf("Please specify exactly one keyfile")
	}
	pubkey, err := PubkeyFromKeyfile(args[0])
	if err != nil {
		log.Fatalf("Unable to get public key from the file: %v", err)
	}
	onionAddress, err := onionutil.OnionAddress(pubkey)
	if err != nil {
		log.Fatalf("Unable to calculate onion address based on public key: %v", err)
	}
	fmt.Printf("%s\n", onionAddress)
}
