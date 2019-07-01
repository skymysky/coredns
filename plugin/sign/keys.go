package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

type Pair struct {
	Public  *dns.DNSKEY
	Tag     uint16
	Private crypto.Signer
}

// readKeyPair read the public and private key from disk. origin is used as the ownername of the
// the DNSKEY record, potentially overwriting the original one.
func readKeyPair(public, private, origin string) (Pair, error) {
	rk, err := os.Open(public)
	if err != nil {
		return Pair{}, err
	}
	b, err := ioutil.ReadAll(rk)
	if err != nil {
		return Pair{}, err
	}
	dnskey, err := dns.NewRR(string(b))
	if err != nil {
		return Pair{}, err
	}
	if _, ok := dnskey.(*dns.DNSKEY); !ok {
		return Pair{}, fmt.Errorf("RR in %q is not a DNSKEY: %d", public, dnskey.Header().Rrtype)
	}
	ksk := dnskey.(*dns.DNSKEY).Flags&(1<<8) == (1<<8) && dnskey.(*dns.DNSKEY).Flags&1 == 1
	if !ksk {
		return Pair{}, fmt.Errorf("DNSKEY in %q, DNSKEY is not a CSK/KSK", public)
	}
	dnskey.(*dns.DNSKEY).Header().Name = origin

	rp, err := os.Open(private)
	if err != nil {
		return Pair{}, err
	}
	privkey, err := dnskey.(*dns.DNSKEY).ReadPrivateKey(rp, private)
	if err != nil {
		return Pair{}, err
	}
	switch signer := privkey.(type) {
	case *ecdsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), Tag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	case *ed25519.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), Tag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	case *rsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), Tag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	default:
		return Pair{}, fmt.Errorf("unsupported algorithm %s", signer)
	}
}
