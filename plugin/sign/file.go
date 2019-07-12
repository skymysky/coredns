package sign

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/file/tree"
	"github.com/miekg/dns"
)

// write writes out the zone file to a temporary file which is then move into the correct place.
func (s Sign) write(z *file.Zone) error {
	f, err := ioutil.TempFile(s.directory, "signed-")
	if err != nil {
		return err
	}

	// need better sorting of these records, to make it slightly nicer
	fmt.Fprintln(f, z.Apex.SOA.String())
	for _, rr := range z.Apex.SIGSOA {
		fmt.Fprintln(f, rr.String())
	}
	for _, rr := range z.Apex.NS {
		fmt.Fprintln(f, rr.String())
	}
	for _, rr := range z.Apex.SIGNS {
		fmt.Fprintln(f, rr.String())
	}
	z.Tree.Do(func(e *tree.Elem) bool {
		for _, r := range e.All() {
			fmt.Fprintln(f, r.String())
		}
		return false
	})

	f.Close()
	err = os.Rename(f.Name(), s.signedfile)
	return err
}

// parse parses the zone in filename and returns a new Zone or an error. This
// is similar to the Parse function in the *file* plugin. However when parsing the
// record type RRSIG, DNSKEY, CDNSKEY and CDS are *not* included in the
// returned zone (if encountered).
func parse(f io.Reader, origin, fileName string) (*file.Zone, error) {
	zp := dns.NewZoneParser(f, dns.Fqdn(origin), fileName)
	zp.SetIncludeAllowed(true)
	z := file.NewZone(origin, fileName)
	seenSOA := false

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := zp.Err(); err != nil {
			return nil, err
		}

		switch rr.(type) {
		case *dns.RRSIG, *dns.DNSKEY, *dns.CDNSKEY, *dns.CDS:
			// drop
		case *dns.SOA:
			seenSOA = true
			if err := z.Insert(rr); err != nil {
				return nil, err
			}
		default:
			if err := z.Insert(rr); err != nil {
				return nil, err
			}
		}
	}
	if !seenSOA {
		return nil, fmt.Errorf("file %q has no SOA record", fileName)
	}

	return z, nil
}
