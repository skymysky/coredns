package sign

import (
	"github.com/coredns/coredns/plugin/file"

	"github.com/miekg/dns"
)

// apexNSEC return the NSEC for the apex of the zone.
func apexNSEC(origin string, ttl uint32, z *file.Zone) *dns.NSEC {
	next := origin
	// this SOA, rest split is unfortunate.
	if e, ok := z.Tree.Next(origin); ok {
		next = e.Name() // this doesn't work.
	}

	// Apex has SOA and NS - just add those by default?
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: origin, Ttl: ttl, Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: next,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA},
	}

	return nsec
}
