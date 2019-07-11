package sign

import (
	"fmt"
	"os"
	"time"

	"github.com/coredns/coredns/plugin/file/tree"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

// Sign holds the data need to sign a zone file.
type Sign struct {
	keys   []Pair
	origin string

	expiration uint32
	inception  uint32
	ttl        uint32

	directory  string
	dbfile     string
	signedfile string
}

var log = clog.NewWithPlugin("sign")

func (s Sign) signFunc(e *tree.Elem) bool {
	// all types that should not be signed, have been dropped when reading the zone, see parse.
	for _, rrs := range e.M() {
		for _, pair := range s.keys {
			rrsig, err := pair.signRRs(rrs, s.origin, s.ttl, s.inception, s.expiration)
			if err != nil {
				return true
			}
			e.Insert(rrsig)
		}
	}

	return false
}

// Sign signs a zone file according to the parameters in s.
func (s Sign) Sign(origin string) error {
	now := time.Now()

	rd, err := os.Open(s.dbfile)
	if err != nil {
		return err
	}

	z, err := parse(rd, origin, s.dbfile)
	if err != nil {
		return err
	}

	s.inception, s.expiration = lifetime(time.Now().UTC())
	s.origin = origin

	s.ttl = z.Apex.SOA.Header().Ttl
	z.Apex.SOA.Serial = uint32(time.Now().Unix())

	for _, pair := range s.keys {
		z.Insert(pair.Public.ToDS(dns.SHA1))
		z.Insert(pair.Public.ToDS(dns.SHA256))
		z.Insert(pair.Public.ToCDNSKEY())
	}
	for _, pair := range s.keys {
		rrsig, err := pair.signRRs([]dns.RR{z.Apex.SOA}, s.origin, s.ttl, s.inception, s.expiration)
		if err != nil {
			return err
		}
		z.Insert(rrsig)
		rrsig, err = pair.signRRs(z.Apex.NS, s.origin, s.ttl, s.inception, s.expiration)
		if err != nil {
			return err
		}
		z.Insert(rrsig)
	}

	// clean up once file things are merged
	if z.Tree.Do(s.signFunc) {
		return fmt.Errorf("error occured")
	}

	s.write(z) // error handling, once booleans are gone

	log.Infof("Signed %q with %d key(s) in %s, saved in %q", origin, len(s.keys), time.Since(now), s.signedfile)

	return nil
}

func lifetime(now time.Time) (uint32, uint32) {
	incep := uint32(now.Add(-3 * time.Hour).Unix()) // -(2+1) hours, be sure to catch daylight saving time and such
	expir := uint32(now.Add(threeWeeks).Unix())     // sign for 21 days
	return incep, expir
}

const threeWeeks = 3 * 7 * 24 * time.Hour
