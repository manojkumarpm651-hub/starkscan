package scan

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// encodeUTF16 builds the on-disk form of a UTF-16 file, optionally with a BOM,
// so the tests exercise real byte layouts rather than assumptions about them.
func encodeUTF16(s string, bigEndian, bom bool) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2+2)
	put := func(u uint16) {
		var b [2]byte
		if bigEndian {
			binary.BigEndian.PutUint16(b[:], u)
		} else {
			binary.LittleEndian.PutUint16(b[:], u)
		}
		out = append(out, b[0], b[1])
	}
	if bom {
		put(0xFEFF)
	}
	for _, u := range units {
		put(u)
	}
	return out
}

func TestDetectEncoding(t *testing.T) {
	const sample = "aws_key: AKIA0000000000000000\npassword: hunter2\n"

	cases := []struct {
		name string
		in   []byte
		want Encoding
	}{
		{"utf16le with bom", encodeUTF16(sample, false, true), EncodingUTF16LE},
		{"utf16be with bom", encodeUTF16(sample, true, true), EncodingUTF16BE},
		{"utf16le without bom", encodeUTF16(sample, false, false), EncodingUTF16LE},
		{"utf16be without bom", encodeUTF16(sample, true, false), EncodingUTF16BE},
		{"plain ascii", []byte(sample), EncodingBytes},
		{"utf8 with accents", []byte("clé: café naïve résumé " + sample), EncodingBytes},
		{"empty", nil, EncodingBytes},
		{"too short to judge", []byte("ab"), EncodingBytes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DetectEncoding(c.in); got != c.want {
				t.Errorf("DetectEncoding = %v, want %v", got, c.want)
			}
		})
	}
}

// TestDetectEncodingDoesNotClaimBinaries guards the risk that comes with the
// fix: deciding a real binary is UTF-16 would feed garbage to every text rule.
func TestDetectEncodingDoesNotClaimBinaries(t *testing.T) {
	cases := map[string][]byte{
		"PE executable":  append([]byte("MZ\x90\x00\x03\x00\x00\x00"), bytes.Repeat([]byte{0x00, 0x01, 0x02, 0x03}, 64)...),
		"ELF executable": append([]byte{0x7F, 'E', 'L', 'F'}, bytes.Repeat([]byte{0xFF, 0x00, 0xAB, 0x00}, 64)...),
		"zip archive":    append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x14, 0x00, 0x08, 0x00}, 64)...),
		"all zeroes":     make([]byte, 512),
		"utf32le bom":    append([]byte{0xFF, 0xFE, 0x00, 0x00}, make([]byte, 64)...),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := DetectEncoding(body); got != EncodingBytes {
				t.Errorf("%s was classified as %v; text rules would receive nonsense", name, got)
			}
		})
	}
}

func TestDecodeTextRoundTrips(t *testing.T) {
	const sample = "line one\nkey = value\nünïcode ok\n"
	for _, c := range []struct {
		name      string
		bigEndian bool
		bom       bool
	}{
		{"le with bom", false, true},
		{"be with bom", true, true},
		{"le no bom", false, false},
		{"be no bom", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, enc := DecodeText(encodeUTF16(sample, c.bigEndian, c.bom))
			if enc == EncodingBytes {
				t.Fatalf("encoding not detected")
			}
			if string(got) != sample {
				t.Errorf("decoded %q, want %q", got, sample)
			}
			if bytes.ContainsRune(got, rune(0xFEFF)) {
				t.Error("byte-order mark survived into the decoded text")
			}
		})
	}
}

func TestDecodeTextLeavesOtherContentAlone(t *testing.T) {
	in := []byte("ordinary utf-8 text, untouched\n")
	got, enc := DecodeText(in)
	if enc != EncodingBytes {
		t.Fatalf("encoding = %v, want bytes", enc)
	}
	if &got[0] != &in[0] {
		t.Error("content that needs no decoding should be returned without copying")
	}
}

func TestDecodeTextHandlesTruncatedUnit(t *testing.T) {
	// A read capped mid-character leaves an odd trailing byte. Decoding must
	// drop it rather than read past the end or emit a half character.
	const full = "alpha bravo charlie delta echo foxtrot golf hotel india\n"
	body := encodeUTF16(full, false, true)
	got, enc := DecodeText(body[:len(body)-1])
	if enc != EncodingUTF16LE {
		t.Fatalf("encoding = %v, want UTF-16LE", enc)
	}
	if !strings.HasPrefix(full, string(got)) {
		t.Errorf("decoded %q, which is not a prefix of the original", got)
	}
}

// TestUTF16FileIsNotTreatedAsBinary is the regression test for the blind spot:
// a UTF-16 file is half NUL bytes, and judging it by those bytes skipped every
// text rule on it while still counting it as scanned.
func TestUTF16FileIsNotTreatedAsBinary(t *testing.T) {
	body := encodeUTF16("aws_key: AKIA0000000000000000\n", false, true)
	f := NewMemoryFile("config.yml", body)

	if f.IsBinary() {
		t.Fatal("UTF-16 text was judged binary; every text rule would be skipped")
	}
	if f.Encoding() != EncodingUTF16LE {
		t.Errorf("Encoding = %v, want UTF-16LE", f.Encoding())
	}
	if !bytes.Contains(f.Text(), []byte("aws_key")) {
		t.Errorf("decoded text does not contain the original content: %q", f.Text())
	}
}

func TestRealBinaryIsStillBinary(t *testing.T) {
	body := append([]byte("MZ\x90\x00"), bytes.Repeat([]byte{0x00, 0x01}, 200)...)
	if !NewMemoryFile("app.exe", body).IsBinary() {
		t.Error("a PE image must still be treated as binary")
	}
}

func TestLineNumbersFollowDecodedText(t *testing.T) {
	// Line numbers must describe the file as a person reads it, not as bytes
	// land on disk - in UTF-16 every offset would otherwise be doubled.
	f := NewMemoryFile("c.yml", encodeUTF16("alpha\nbravo\ncharlie\n", false, true))
	idx := bytes.Index(f.Text(), []byte("charlie"))
	if idx < 0 {
		t.Fatal("decoded text missing expected content")
	}
	if got := f.LineAt(idx); got != 3 {
		t.Errorf("LineAt(charlie) = %d, want 3", got)
	}
}
