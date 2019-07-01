package sign

import "testing"

func TestSign(t *testing.T) {
	s := &Sign{}
	s.dbfile = "db.miek.nl"
	s.signedfile = "db.miek.nl.signed"
	s.directory = "."
	pair, err := readKeyPair("Kmiek.nl.+013+59725.key", "Kmiek.nl.+013+59725.private", "miek.nl.")
	if err != nil {
		t.Fatal(err)
	}

	s.keys = []Pair{pair}
	if err := s.Sign("miek.nl."); err != nil {
		t.Error(err)
	}
}
