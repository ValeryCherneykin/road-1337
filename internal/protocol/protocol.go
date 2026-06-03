// Package protocol defines the binary wire protocol for road-1337.
// All network-level frames are strictly typed, memory-aligned, and structured here.
// Any breaking protocol changes require incrementing the protocol version.
package protocol

import (
	"encoding/binary"
	"fmt"
)

// Version represents the current iteration of the wire protocol.
// It must be incremented whenever backward-incompatible changes are introduced.
const Version = uint8(1)

// PacketType defines the single-byte identifier in the protocol header.
type PacketType uint8

const (
	// TypeHandshake is the initial unencrypted frame containing the sender's
	// public key and routing target hash.
	TypeHandshake PacketType = 0x01

	// TypeMessage represents an encrypted text payload.
	TypeMessage PacketType = 0x02

	// TypeFileChunk represents an encrypted binary slice of a file.
	TypeFileChunk PacketType = 0x03

	// TypeFileHeader carries metadata (name, size) before file transmission begins.
	TypeFileHeader PacketType = 0x04

	// TypeFileEOF signals the successful completion of a file transfer.
	TypeFileEOF PacketType = 0x05

	// TypePing serves as a keepalive frame to maintain NAT mappings and server routing state.
	TypePing PacketType = 0x06

	// TypePong acts as the immediate mandatory response to a TypePing frame.
	TypePong PacketType = 0x07

	// TypeDisconnect indicates a graceful, intentional connection teardown.
	TypeDisconnect PacketType = 0x08
)

// HandshakePayloadSize represents the exact size of an unencrypted handshake packet.
// Layout: version(1B) + sender_pubkey(32B) + recipient_pubkey_hash(32B) = 65 bytes.
const HandshakePayloadSize = 1 + 32 + 32

// ChunkSize defines the standard memory boundary for file slicing (512 KB).
const ChunkSize = 512 * 1024

// WireHeader defines the 5-byte structural prefix for all payload types.
// During transit, this header is encrypted alongside the data payload,
// keeping routing-internal details invisible to intermediate transport nodes.
//
// Structural Layout:
//
//	[PacketType: 1 byte][ChunkIndex: 4 bytes (Big-Endian)][Payload: N bytes]
type WireHeader struct {
	Type       PacketType
	ChunkIndex uint32 // Sequence number for file chunks; defaults to 0 for standard messages.
}

// HeaderSize defines the absolute byte length of the serialized WireHeader.
const HeaderSize = 1 + 4

// Encode serializes the WireHeader into a fixed 5-byte slice using Network Byte Order (Big-Endian).
func (h WireHeader) Encode() []byte {
	buf := make([]byte, HeaderSize)
	buf[0] = byte(h.Type)
	binary.BigEndian.PutUint32(buf[1:], h.ChunkIndex)
	return buf
}

// DecodeHeader deserializes a WireHeader from the initial 5 bytes of a incoming payload buffer.
// Returns the parsed header struct and slices away the consumed header bytes.
func DecodeHeader(payload []byte) (WireHeader, []byte, error) {
	if len(payload) < HeaderSize {
		return WireHeader{}, nil, fmt.Errorf("payload too short for header: %d < %d", len(payload), HeaderSize)
	}
	h := WireHeader{
		Type:       PacketType(payload[0]),
		ChunkIndex: binary.BigEndian.Uint32(payload[1:5]),
	}
	return h, payload[HeaderSize:], nil
}

// BuildMessage wraps raw data with a standard WireHeader (ChunkIndex = 0) for encryption delivery.
func BuildMessage(ptype PacketType, data []byte) []byte {
	h := WireHeader{Type: ptype, ChunkIndex: 0}
	hdr := h.Encode()
	payload := make([]byte, len(hdr)+len(data))
	copy(payload, hdr)
	copy(payload[len(hdr):], data)
	return payload
}

// BuildFileChunk packages a specific file partition with its sequence index into a valid wire payload.
func BuildFileChunk(chunkIndex uint32, ptype PacketType, data []byte) []byte {
	h := WireHeader{Type: ptype, ChunkIndex: chunkIndex}
	hdr := h.Encode()
	payload := make([]byte, len(hdr)+len(data))
	copy(payload, hdr)
	copy(payload[len(hdr):], data)
	return payload
}

// FileHeaderPayload encapsulates the filesystem metadata transmitted before structural data chunks.
type FileHeaderPayload struct {
	Filename    string
	TotalSize   uint64
	TotalChunks uint32
}

// EncodeFileHeader serializes file metadata into a binary stream.
// Layout: totalSize(8B) + totalChunks(4B) + filenameLen(2B) + filename(NB)
func EncodeFileHeader(fh FileHeaderPayload) ([]byte, error) {
	nameBytes := []byte(fh.Filename)
	if len(nameBytes) > 255 {
		return nil, fmt.Errorf("filename too long: %d > 255", len(nameBytes))
	}
	buf := make([]byte, 8+4+2+len(nameBytes))
	binary.BigEndian.PutUint64(buf[0:], fh.TotalSize)
	binary.BigEndian.PutUint32(buf[8:], fh.TotalChunks)
	binary.BigEndian.PutUint16(buf[12:], uint16(len(nameBytes)))
	copy(buf[14:], nameBytes)
	return buf, nil
}

// DecodeFileHeader decodes raw binary data back into a structured FileHeaderPayload.
func DecodeFileHeader(data []byte) (FileHeaderPayload, error) {
	if len(data) < 14 {
		return FileHeaderPayload{}, fmt.Errorf("file header too short: %d", len(data))
	}
	totalSize := binary.BigEndian.Uint64(data[0:])
	totalChunks := binary.BigEndian.Uint32(data[8:])
	nameLen := binary.BigEndian.Uint16(data[12:])
	if int(14+nameLen) > len(data) {
		return FileHeaderPayload{}, fmt.Errorf("truncated filename in header")
	}
	return FileHeaderPayload{
		Filename:    string(data[14 : 14+nameLen]),
		TotalSize:   totalSize,
		TotalChunks: totalChunks,
	}, nil
}

// HandshakePayload represents the initial, unencrypted framing of a TCP connection.
// It allows the transit server to route packets via the RecipientKeyHash without
// exposing the sender's actual identity or compromising message secrecy.
type HandshakePayload struct {
	Version          uint8
	SenderPubKey     [32]byte // Ephemeral or static public identity key of the sender.
	RecipientKeyHash [32]byte // SHA-256 hash of the target public key for blind server routing.
}

// EncodeHandshake formats the HandshakePayload into a strict 65-byte array.
func EncodeHandshake(h HandshakePayload) []byte {
	buf := make([]byte, HandshakePayloadSize)
	buf[0] = h.Version
	copy(buf[1:33], h.SenderPubKey[:])
	copy(buf[33:65], h.RecipientKeyHash[:])
	return buf
}

// DecodeHandshake extracts HandshakePayload metrics from a raw 65-byte network slice.
func DecodeHandshake(data []byte) (HandshakePayload, error) {
	if len(data) < HandshakePayloadSize {
		return HandshakePayload{}, fmt.Errorf("handshake too short: %d < %d", len(data), HandshakePayloadSize)
	}
	var h HandshakePayload
	h.Version = data[0]
	copy(h.SenderPubKey[:], data[1:33])
	copy(h.RecipientKeyHash[:], data[33:65])
	return h, nil
}
