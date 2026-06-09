// Package relay — integration tests for the Blind Relay server.
package relay

import (
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ValeryCherneykin/road-1337/internal/crypto"
	"github.com/ValeryCherneykin/road-1337/internal/protocol"
)

// waitReady attempts to connect to addr until success or timeout.
// Needed because srv.Run() binds asynchronously in the test goroutine.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready within 2s", addr)
}

// connect dials the relay and sends the opening handshake.
func connect(t *testing.T, addr string, kp *crypto.KeyPair, target [32]byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var pub [32]byte
	copy(pub[:], kp.PublicKeyBytes())
	hs := protocol.EncodeHandshake(protocol.HandshakePayload{
		Version: protocol.Version, SenderPubKey: pub, RecipientKeyHash: target,
	})
	if _, err := conn.Write(hs); err != nil {
		t.Fatal(err)
	}
	return conn
}

// TestRelayRouting is the core E2EE routing correctness test:
// a packet from A addressed to B's hash arrives at B, decryptable with
// the ECDH shared key. The relay never sees plaintext.
func TestRelayRouting(t *testing.T) {
	srv := New()
	ready := make(chan struct{})
	go func() {
		close(ready)
		srv.Run(":18337") //nolint:errcheck
	}()
	<-ready
	waitReady(t, ":18337")
	defer srv.Stop()

	kpA, _ := crypto.GenerateKeyPair()
	kpB, _ := crypto.GenerateKeyPair()
	defer kpA.Zeroize()
	defer kpB.Zeroize()

	hashA := sha256.Sum256(kpA.PublicKeyBytes())
	hashB := sha256.Sum256(kpB.PublicKeyBytes())

	connA := connect(t, "127.0.0.1:18337", kpA, hashB)
	connB := connect(t, "127.0.0.1:18337", kpB, hashA)
	defer func() {
		_ = connA.Close()
	}()
	defer func() {
		_ = connB.Close()
	}()
	time.Sleep(50 * time.Millisecond)

	if n := srv.PeerCount(); n != 2 {
		t.Fatalf("want 2 peers, got %d", n)
	}

	sharedA, _ := kpA.ECDH(kpB.PublicKeyBytes())
	sharedB, _ := kpB.ECDH(kpA.PublicKeyBytes())
	defer clear(sharedA)
	defer clear(sharedB)

	sessA, _ := crypto.NewSession(sharedA)
	sessB, _ := crypto.NewSession(sharedB)
	defer sessA.Zeroize()
	defer sessB.Zeroize()

	const wantText = "hello from alice via blind relay"
	payload := protocol.BuildMessage(protocol.TypeMessage, []byte(wantText))
	enc, _ := sessA.Seal(payload)

	frame := make([]byte, 32+crypto.PacketSize)
	copy(frame[:32], hashB[:])
	copy(frame[32:], enc)
	if _, err := connA.Write(frame); err != nil {
		t.Fatalf("failed to write to connA: %v", err)
	}

	if err := connB.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline on connB: %v", err)
	}
	pkt := make([]byte, crypto.PacketSize)
	if _, err := io.ReadFull(connB, pkt); err != nil {
		t.Fatalf("Bob did not receive packet: %v", err)
	}

	plain, err := sessB.Open(pkt)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	hdr, body, _ := protocol.DecodeHeader(plain)
	if hdr.Type != protocol.TypeMessage {
		t.Fatalf("want TypeMessage (0x%02x), got 0x%02x", protocol.TypeMessage, hdr.Type)
	}
	if string(body) != wantText {
		t.Fatalf("want %q, got %q", wantText, body)
	}
	t.Logf("✓ relay routing: Bob received %q", string(body))
}

// TestRelayBidirectional verifies A→B and B→A both work in the same session.
func TestRelayBidirectional(t *testing.T) {
	srv := New()
	go srv.Run(":18338") //nolint:errcheck
	waitReady(t, ":18338")
	defer srv.Stop()

	kpA, _ := crypto.GenerateKeyPair()
	kpB, _ := crypto.GenerateKeyPair()
	defer kpA.Zeroize()
	defer kpB.Zeroize()

	hashA := sha256.Sum256(kpA.PublicKeyBytes())
	hashB := sha256.Sum256(kpB.PublicKeyBytes())

	connA := connect(t, "127.0.0.1:18338", kpA, hashB)
	connB := connect(t, "127.0.0.1:18338", kpB, hashA)
	defer func() {
		_ = connA.Close()
	}()
	defer func() {
		_ = connB.Close()
	}()
	time.Sleep(50 * time.Millisecond)

	sA, _ := kpA.ECDH(kpB.PublicKeyBytes())
	sB, _ := kpB.ECDH(kpA.PublicKeyBytes())
	defer clear(sA)
	defer clear(sB)

	sessA, _ := crypto.NewSession(sA)
	sessB, _ := crypto.NewSession(sB)
	defer sessA.Zeroize()
	defer sessB.Zeroize()

	send := func(from net.Conn, sess *crypto.Session, toHash [32]byte, msg string) {
		payload := protocol.BuildMessage(protocol.TypeMessage, []byte(msg))
		enc, _ := sess.Seal(payload)
		frame := make([]byte, 32+crypto.PacketSize)
		copy(frame[:32], toHash[:])
		copy(frame[32:], enc)

		if _, err := from.Write(frame); err != nil {
			t.Fatalf("failed to write frame: %v", err)
		}
	}

	recv := func(conn net.Conn, sess *crypto.Session) string {
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("failed to set read deadline: %v", err)
		}
		pkt := make([]byte, crypto.PacketSize)
		if _, err := io.ReadFull(conn, pkt); err != nil {
			t.Fatalf("did not receive packet: %v", err)
		}
		plain, _ := sess.Open(pkt)
		_, body, _ := protocol.DecodeHeader(plain)
		return string(body)
	}

	send(connA, sessA, hashB, "A→B")
	if got := recv(connB, sessB); got != "A→B" {
		t.Fatalf("A→B: want %q, got %q", "A→B", got)
	}

	send(connB, sessB, hashA, "B→A")
	if got := recv(connA, sessA); got != "B→A" {
		t.Fatalf("B→A: want %q, got %q", "B→A", got)
	}
	t.Log("✓ bidirectional relay works")
}

// TestRelayStopIdempotent verifies Stop() is safe to call concurrently.
func TestRelayStopIdempotent(t *testing.T) {
	srv := New()
	go srv.Run(":18340") //nolint:errcheck
	waitReady(t, ":18340")

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); srv.Stop() }()
	}
	wg.Wait()
	t.Log("✓ Stop() is idempotent")
}

// TestRelaySnapshot verifies that connected peers appear in Snapshot().
func TestRelaySnapshot(t *testing.T) {
	srv := New()
	go srv.Run(":18341") //nolint:errcheck
	waitReady(t, ":18341")
	defer srv.Stop()

	kp, _ := crypto.GenerateKeyPair()
	defer kp.Zeroize()
	hash := sha256.Sum256(kp.PublicKeyBytes())

	conn := connect(t, "127.0.0.1:18341", kp, hash)
	defer func() {
		_ = conn.Close()
	}()
	time.Sleep(50 * time.Millisecond)

	snap := srv.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 peer in snapshot, got %d", len(snap))
	}
	if snap[0].RemoteAddr == "" {
		t.Fatal("RemoteAddr should not be empty")
	}
	t.Logf("✓ snapshot: hash=%s addr=%s", snap[0].KeyHashHex, snap[0].RemoteAddr)
}
