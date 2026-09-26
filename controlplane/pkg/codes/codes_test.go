package codes

import "testing"

func TestRoundTrip(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != Length+4 {
		t.Fatalf("display len %d: %q", len(c), c)
	}
	n, err := Normalize(c)
	if err != nil {
		t.Fatal(err)
	}
	h := Hash(n)
	if !Match(c, h) {
		t.Fatal("exact form should match")
	}
	if !Match("  "+c+"\n", h) {
		t.Fatal("whitespace should be ignored")
	}
	lower := []byte(c)
	for i := range lower {
		if lower[i] >= 'A' && lower[i] <= 'Z' {
			lower[i] += 'a' - 'A'
		}
	}
	if !Match(string(lower), h) {
		t.Fatal("lowercase should match")
	}
	if Match(c[:len(c)-1]+"0", h) && c[len(c)-1] != '0' {
		t.Fatal("altered code matched")
	}
	if _, err := Normalize("ABC"); err == nil {
		t.Fatal("short code accepted")
	}
	if _, err := Normalize("ABCD-EFGH-JKMN-PQRS-TVW!"); err == nil {
		t.Fatal("bad char accepted")
	}
}

func TestAmbiguousGlyphs(t *testing.T) {
	n1, _ := Normalize("0123-4567-89AB-CDEF-GHJK")
	n2, _ := Normalize("O123-4567-89AB-CDEF-GHJK")
	n3, _ := Normalize("0I23-4567-89AB-CDEF-GHJK")
	if n1 != n2 || n1 != n3 {
		t.Fatalf("glyph mapping: %s %s %s", n1, n2, n3)
	}
}
