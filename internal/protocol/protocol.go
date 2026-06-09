// Package protocol defines the binary wire protocol for road-1337.
//
// All network frames are strictly typed and versioned.
// Breaking changes require incrementing Version.
//
// File transfer design:
//
//	File transfer state is managed via explicit signaling.
//	1. TypeFileHeader initializes the transfer metadata.
//	2. TypeFileChunk delivers the binary payload.
//	3. TypeFileEOF explicitly terminates the stream.
//	This guarantees deterministic teardown regardless of byte counts.
package protocol

import (
	"encoding/binary"
	"fmt"
)

// Version must be incremented on any backward-incompatible protocol change.
const Version = uint8(1)

// PacketType identifies the payload kind in every encrypted frame.
type PacketType uint8

const (
	TypeHandshake  PacketType = 0x01 // unencrypted opening frame
	TypeMessage    PacketType = 0x02 // plain text message
	TypeFileHeader PacketType = 0x03 // file transfer metadata
	TypeFileChunk  PacketType = 0x04 // file data slice
	TypePing       PacketType = 0x05 // keepalive request
	TypePong       PacketType = 0x06 // keepalive response
	TypeDisconnect PacketType = 0x07 // graceful session teardown
	TypeFileEOF    PacketType = 0x08 // explicit end of file transfer
)

// HandshakePayloadSize is the exact byte length of the unencrypted opening frame.
//
//	version(1) + sender_pub_key(32) + recipient_key_hash(32) = 65 bytes
const HandshakePayloadSize = 1 + 32 + 32

// ChunkSize is the buffer size used to read files in blocks.
// 128 KB fits comfortably and efficiently reduces disk I/O syscalls.
// Each block is split into multiple PacketSize sub-packets on the wire.
const ChunkSize = 128 * 1024 // 128 KB

// WireHeader is the encrypted prefix of every application payload.
//
// Layout (9 bytes, big-endian):
//
//	[Type:1][ChunkIndex:4][FileID:4]
//
// FileID uniquely identifies a file transfer (crypto/rand uint32).
// For non-file packets, FileID and ChunkIndex are both 0.
type WireHeader struct {
	Type       PacketType
	ChunkIndex uint32 // sequence number within a file transfer; 0 for messages
	FileID     uint32 // unique transfer identifier; 0 for non-file packets
}

// HeaderSize is the serialized byte length of WireHeader.
const HeaderSize = 1 + 4 + 4 // 9 bytes

// Encode serializes WireHeader into exactly 9 bytes (big-endian).
func (h WireHeader) Encode() []byte {
	buf := make([]byte, HeaderSize)
	buf[0] = byte(h.Type)
	binary.BigEndian.PutUint32(buf[1:5], h.ChunkIndex)
	binary.BigEndian.PutUint32(buf[5:9], h.FileID)
	return buf
}

// DecodeHeader parses the leading 9 bytes and returns the remaining payload.
func DecodeHeader(payload []byte) (WireHeader, []byte, error) {
	if len(payload) < HeaderSize {
		return WireHeader{}, nil, fmt.Errorf(
			"payload too short for header: got %d, need %d", len(payload), HeaderSize,
		)
	}
	h := WireHeader{
		Type:       PacketType(payload[0]),
		ChunkIndex: binary.BigEndian.Uint32(payload[1:5]),
		FileID:     binary.BigEndian.Uint32(payload[5:9]),
	}
	return h, payload[HeaderSize:], nil
}

// BuildMessage wraps data with a standard WireHeader (no file context).
func BuildMessage(ptype PacketType, data []byte) []byte {
	hdr := WireHeader{Type: ptype}.Encode()
	out := make([]byte, len(hdr)+len(data))
	copy(out, hdr)
	copy(out[len(hdr):], data)
	return out
}

// BuildFileChunk wraps a file data slice with its transfer ID and sequence number.
// Can also be used to send TypeFileEOF by passing a nil or empty data slice.
func BuildFileChunk(fileID, chunkIndex uint32, data []byte) []byte {
	hdr := WireHeader{
		Type:       TypeFileChunk,
		ChunkIndex: chunkIndex,
		FileID:     fileID,
	}.Encode()
	out := make([]byte, len(hdr)+len(data))
	copy(out, hdr)
	copy(out[len(hdr):], data)
	return out
}

// BuildFileEOF creates an explicit termination packet for a file transfer.
func BuildFileEOF(fileID uint32) []byte {
	return WireHeader{
		Type:   TypeFileEOF,
		FileID: fileID,
	}.Encode()
}

// FileHeaderPayload contains the metadata sent before any file chunks.
type FileHeaderPayload struct {
	Filename    string
	TotalSize   uint64
	TotalChunks uint32
	FileID      uint32 // must match the FileID used in subsequent BuildFileChunk/EOF calls
}

// EncodeFileHeader serializes FileHeaderPayload.
//
// Layout:
//
//	TotalSize(8) + TotalChunks(4) + FileID(4) + nameLen(2) + Filename(N)
func EncodeFileHeader(fh FileHeaderPayload) ([]byte, error) {
	name := []byte(fh.Filename)
	if len(name) > 255 {
		return nil, fmt.Errorf("filename too long: %d > 255 bytes", len(name))
	}
	buf := make([]byte, 8+4+4+2+len(name))
	binary.BigEndian.PutUint64(buf[0:], fh.TotalSize)
	binary.BigEndian.PutUint32(buf[8:], fh.TotalChunks)
	binary.BigEndian.PutUint32(buf[12:], fh.FileID)
	binary.BigEndian.PutUint16(buf[16:], uint16(len(name)))
	copy(buf[18:], name)
	return buf, nil
}

// DecodeFileHeader parses a binary FileHeaderPayload.
func DecodeFileHeader(data []byte) (FileHeaderPayload, error) {
	if len(data) < 18 {
		return FileHeaderPayload{}, fmt.Errorf("file header too short: %d bytes", len(data))
	}
	nameLen := int(binary.BigEndian.Uint16(data[16:]))

	if 18+nameLen > len(data) {
		return FileHeaderPayload{}, fmt.Errorf("truncated filename in file header")
	}

	return FileHeaderPayload{
		TotalSize:   binary.BigEndian.Uint64(data[0:]),
		TotalChunks: binary.BigEndian.Uint32(data[8:]),
		FileID:      binary.BigEndian.Uint32(data[12:]),
		Filename:    string(data[18 : 18+nameLen]),
	}, nil
}

// HandshakePayload is the only unencrypted frame in the session.
// It lets the relay register the sender and record the routing destination
// without ever seeing session key material.
type HandshakePayload struct {
	Version          uint8
	SenderPubKey     [32]byte // relay registers this peer under SHA-256(SenderPubKey)
	RecipientKeyHash [32]byte // SHA-256 of the target peer's public key
}

// EncodeHandshake serializes HandshakePayload into exactly 65 bytes.
func EncodeHandshake(h HandshakePayload) []byte {
	buf := make([]byte, HandshakePayloadSize)
	buf[0] = h.Version
	copy(buf[1:33], h.SenderPubKey[:])
	copy(buf[33:65], h.RecipientKeyHash[:])
	return buf
}

// DecodeHandshake parses a 65-byte handshake frame.
func DecodeHandshake(data []byte) (HandshakePayload, error) {
	if len(data) < HandshakePayloadSize {
		return HandshakePayload{}, fmt.Errorf(
			"handshake too short: got %d, need %d", len(data), HandshakePayloadSize,
		)
	}
	var h HandshakePayload
	h.Version = data[0]
	copy(h.SenderPubKey[:], data[1:33])
	copy(h.RecipientKeyHash[:], data[33:65])
	return h, nil
}
