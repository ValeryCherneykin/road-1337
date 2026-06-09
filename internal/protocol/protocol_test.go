// Package protocol — tests for wire protocol serialization.
package protocol

import (
	"bytes"
	"testing"
)

func TestWireHeaderEncoDecode(t *testing.T) {
	h := WireHeader{Type: TypeFileChunk, ChunkIndex: 42, FileID: 999}
	encoded := h.Encode()

	if len(encoded) != HeaderSize {
		t.Fatalf("Encode size: got %d, want %d", len(encoded), HeaderSize)
	}

	got, rest, err := DecodeHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected remainder: %d bytes", len(rest))
	}
	if got != h {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, h)
	}
}

func TestDecodeHeaderTooShort(t *testing.T) {
	_, _, err := DecodeHeader([]byte{0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for short header, got nil")
	}
}

func TestBuildMessage(t *testing.T) {
	data := []byte("hello")
	payload := BuildMessage(TypeMessage, data)
	if len(payload) != HeaderSize+len(data) {
		t.Fatalf("BuildMessage length: got %d, want %d", len(payload), HeaderSize+len(data))
	}
	hdr, body, err := DecodeHeader(payload)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Type != TypeMessage {
		t.Fatalf("type: got %d, want %d", hdr.Type, TypeMessage)
	}
	if !bytes.Equal(body, data) {
		t.Fatalf("body mismatch")
	}
}

func TestBuildFileChunk(t *testing.T) {
	data := []byte("chunk data")
	payload := BuildFileChunk(1337, 7, data)
	hdr, body, err := DecodeHeader(payload)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Type != TypeFileChunk {
		t.Fatalf("type: got %d", hdr.Type)
	}
	if hdr.FileID != 1337 {
		t.Fatalf("FileID: got %d", hdr.FileID)
	}
	if hdr.ChunkIndex != 7 {
		t.Fatalf("ChunkIndex: got %d", hdr.ChunkIndex)
	}
	if !bytes.Equal(body, data) {
		t.Fatal("body mismatch")
	}
}

func TestFileHeaderRoundTrip(t *testing.T) {
	fh := FileHeaderPayload{
		Filename:    "passport.jpg",
		TotalSize:   1024 * 1024,
		TotalChunks: 2,
		FileID:      0xDEADBEEF,
	}
	encoded, err := EncodeFileHeader(fh)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeFileHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Filename != fh.Filename {
		t.Fatalf("Filename: %q != %q", decoded.Filename, fh.Filename)
	}
	if decoded.TotalSize != fh.TotalSize {
		t.Fatalf("TotalSize: %d != %d", decoded.TotalSize, fh.TotalSize)
	}
	if decoded.TotalChunks != fh.TotalChunks {
		t.Fatalf("TotalChunks")
	}
	if decoded.FileID != fh.FileID {
		t.Fatalf("FileID: %d != %d", decoded.FileID, fh.FileID)
	}
}

func TestFileHeaderTooLongName(t *testing.T) {
	fh := FileHeaderPayload{Filename: string(make([]byte, 256))}
	_, err := EncodeFileHeader(fh)
	if err == nil {
		t.Fatal("expected error for filename > 255 bytes")
	}
}

func TestHandshakeRoundTrip(t *testing.T) {
	var pub, hash [32]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	for i := range hash {
		hash[i] = byte(i + 128)
	}

	hs := HandshakePayload{
		Version:          Version,
		SenderPubKey:     pub,
		RecipientKeyHash: hash,
	}
	encoded := EncodeHandshake(hs)
	if len(encoded) != HandshakePayloadSize {
		t.Fatalf("encoded size: got %d, want %d", len(encoded), HandshakePayloadSize)
	}

	decoded, err := DecodeHandshake(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Version != hs.Version {
		t.Fatalf("Version")
	}
	if decoded.SenderPubKey != hs.SenderPubKey {
		t.Fatalf("SenderPubKey")
	}
	if decoded.RecipientKeyHash != hs.RecipientKeyHash {
		t.Fatalf("RecipientKeyHash")
	}
}
