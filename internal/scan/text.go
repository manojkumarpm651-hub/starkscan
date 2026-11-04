package scan

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

// Encoding is how a file's bytes spell out text.
type Encoding int

const (
	// EncodingBytes means the content is used as-is: UTF-8, some other
	// 8-bit encoding, or not text at all.
	EncodingBytes Encoding = iota
	EncodingUTF16LE
	EncodingUTF16BE
)

func (e Encoding) String() string {
	switch e {
	case EncodingUTF16LE:
		return "UTF-16LE"
	case EncodingUTF16BE:
		return "UTF-16BE"
	}
	return "bytes"
}

// sniffLimit is how much of a file is examined to guess its encoding. The
// pattern UTF-16 leaves is extremely regular, so a small sample settles it.
const sniffLimit = 8192

// DetectEncoding identifies UTF-16 content, by byte-order mark where one is
// present and by the shape of the bytes where it is not.
//
// This matters more than it first appears. A NUL byte is the usual signal that
// a file is binary, and UTF-16 text is half NUL bytes, so without this every
// UTF-16 file would be written off as binary and skipped by every text rule.
// Windows produces UTF-16 routinely - redirected PowerShell output, exported
// registry data, plenty of configuration tools - so those would not be exotic
// misses, they would be everyday ones.
func DetectEncoding(b []byte) Encoding {
	candidate := bomEncoding(b)
	if candidate == EncodingBytes {
		candidate = nulPatternEncoding(b)
	}
	if candidate == EncodingBytes {
		return EncodingBytes
	}
	// Byte positions alone are not enough. An ELF image, a zip header or any
	// structure of 16-bit little-endian fields puts a zero in every other byte
	// exactly as Latin UTF-16 does, so a NUL-position test on its own promotes
	// binaries to text and hands every rule decoded nonsense. The deciding
	// question is whether the result reads as text.
	if !decodesToText(b, candidate) {
		return EncodingBytes
	}
	return candidate
}

// bomEncoding reads an explicit byte-order mark, if the file declares one.
func bomEncoding(b []byte) Encoding {
	if len(b) < 2 {
		return EncodingBytes
	}
	// A UTF-32LE file starts FF FE 00 00 and must not be mistaken for UTF-16LE
	// followed by a NUL character.
	if b[0] == 0xFF && b[1] == 0xFE {
		if len(b) >= 4 && b[2] == 0x00 && b[3] == 0x00 {
			return EncodingBytes
		}
		return EncodingUTF16LE
	}
	if b[0] == 0xFE && b[1] == 0xFF {
		return EncodingUTF16BE
	}
	return EncodingBytes
}

// nulPatternEncoding guesses from where the zero bytes fall. Latin text in
// UTF-16 puts a NUL in the high byte of nearly every unit: the odd byte for
// little endian, the even byte for big endian.
func nulPatternEncoding(b []byte) Encoding {
	sample := b
	if len(sample) > sniffLimit {
		sample = sample[:sniffLimit]
	}
	if len(sample) < 16 {
		return EncodingBytes
	}
	// An odd length cannot be whole UTF-16 code units; examine complete pairs.
	sample = sample[:len(sample)&^1]

	var evenNUL, oddNUL int
	for i := 0; i < len(sample); i += 2 {
		if sample[i] == 0 {
			evenNUL++
		}
		if sample[i+1] == 0 {
			oddNUL++
		}
	}
	pairs := float64(len(sample) / 2)

	const strong = 0.60
	const quiet = 0.10
	switch {
	case float64(oddNUL)/pairs >= strong && float64(evenNUL)/pairs <= quiet:
		return EncodingUTF16LE
	case float64(evenNUL)/pairs >= strong && float64(oddNUL)/pairs <= quiet:
		return EncodingUTF16BE
	}
	return EncodingBytes
}

// decodesToText reports whether reading the sample in the given encoding
// yields something that reads like text.
//
// The bar is the proportion of plain ASCII, because that is what the rules
// look for: credentials, command lines and configuration keys are ASCII even
// inside a file whose prose is not. A UTF-16 document written wholly in a
// non-Latin script will therefore be treated as bytes and skipped by the text
// rules - a deliberate trade, since it carries nothing those rules can match.
func decodesToText(b []byte, enc Encoding) bool {
	sample := b
	if len(sample) > sniffLimit {
		sample = sample[:sniffLimit]
	}
	sample = sample[:len(sample)&^1]
	if len(sample) < 2 {
		return false
	}

	var ascii, total int
	for i := 0; i+1 < len(sample); i += 2 {
		var u uint16
		if enc == EncodingUTF16LE {
			u = binary.LittleEndian.Uint16(sample[i:])
		} else {
			u = binary.BigEndian.Uint16(sample[i:])
		}
		total++
		switch {
		case u == '\n', u == '\r', u == '\t':
			ascii++
		case u >= 0x20 && u <= 0x7E:
			ascii++
		}
	}
	if total == 0 {
		return false
	}
	const asciiFloor = 0.70
	return float64(ascii)/float64(total) >= asciiFloor
}

// DecodeText returns the content as UTF-8. Content that is not UTF-16 is
// returned unchanged and without copying, so the common path costs nothing.
//
// The returned text is what every text rule matches against, so offsets into
// it - and therefore reported line numbers - refer to the decoded form, which
// is the form a person reading the file in an editor would see.
func DecodeText(b []byte) ([]byte, Encoding) {
	enc := DetectEncoding(b)
	if enc == EncodingBytes {
		return b, enc
	}

	body := b
	// Drop the byte-order mark so it cannot show up inside a finding.
	if len(body) >= 2 {
		if (enc == EncodingUTF16LE && body[0] == 0xFF && body[1] == 0xFE) ||
			(enc == EncodingUTF16BE && body[0] == 0xFE && body[1] == 0xFF) {
			body = body[2:]
		}
	}
	// A read capped mid-character leaves a trailing odd byte; drop it rather
	// than decode a half unit.
	body = body[:len(body)&^1]

	units := make([]uint16, len(body)/2)
	for i := range units {
		if enc == EncodingUTF16LE {
			units[i] = binary.LittleEndian.Uint16(body[i*2:])
		} else {
			units[i] = binary.BigEndian.Uint16(body[i*2:])
		}
	}

	runes := utf16.Decode(units)
	out := make([]byte, 0, len(runes)+len(runes)/2)
	var buf [utf8.UTFMax]byte
	for _, r := range runes {
		n := utf8.EncodeRune(buf[:], r)
		out = append(out, buf[:n]...)
	}
	return out, enc
}

// looksBinary reports whether decoded text still contains a NUL, which is the
// same heuristic git uses. Running it on the decoded form rather than the raw
// bytes is the whole point: UTF-16 text decodes to UTF-8 with no NULs in it.
func looksBinary(text []byte) bool {
	n := len(text)
	if n > sniffLimit {
		n = sniffLimit
	}
	return bytes.IndexByte(text[:n], 0) >= 0
}
