package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	in := message{Type: "hello", Token: "dummy", Name: "world", Port: 30000}
	if err := writeFrame(&b, in); err != nil {
		t.Fatal(err)
	}
	out, err := readFrame(&b)
	if err != nil || out.Token != in.Token || out.Port != in.Port {
		t.Fatalf("roundtrip: %+v %v", out, err)
	}
	for _, n := range []uint32{0, maxFrame + 1, ^uint32(0)} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], n)
		if _, err := readFrame(bytes.NewReader(size[:])); err == nil {
			t.Fatal("accepted oversized/empty frame")
		}
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0})); err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
}

func FuzzFrame(f *testing.F) {
	var b bytes.Buffer
	_ = writeFrame(&b, message{Type: "ping"})
	f.Add(b.Bytes())
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = readFrame(bytes.NewReader(data)) })
}

func BenchmarkFrame(b *testing.B) {
	m := message{Type: "open", Stream: "0123456789abcdef"}
	b.ReportAllocs()
	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = writeFrame(&buf, m)
		_, _ = readFrame(&buf)
	}
}
