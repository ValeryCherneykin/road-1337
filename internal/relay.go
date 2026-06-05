// Package relay implements the road-1337 Blind Relay server.
//
// This is a deliberately minimal, "dumb" relay. Its only responsibility is
// to forward opaque encrypted packets between peers using the SHA-256 hash
// of the recipient's public key as the routing identifier.
//
// The server never:
//   - decrypts any application data
//   - holds session keys
//   - writes anything to disk
//   - logs sensitive information
//
// Security Invariants (must never be violated):
//   - Zero disk I/O: logging is disabled, no files are created.
//   - Burn-on-Read: every buffer is zeroed with clear() immediately after use.
//   - Zero trust: server has no knowledge of plaintext or session secrets.
//   - Graceful shutdown: all goroutines are waited on via sync.WaitGroup.
//   - Memory safety: bounded peer count + sync.Pool to control GC pressure.
package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ValeryCherneykin/road-1337/internal/crypto"
	"github.com/ValeryCherneykin/road-1337/internal/protocol"
)

const (
	recipientHashSize = 32
	outerFrameSize    = recipientHashSize + crypto.PacketSize

	handshakeTimeout = 15 * time.Second
	heartbeatTimeout = 45 * time.Second
	writeTimeout     = 10 * time.Second

	maxPeers      = 2048
	sweepInterval = 15 * time.Second
)

// peer represents one active TCP connection in the routing table.
type peer struct {
	conn      net.Conn
	keyHash   [32]byte // SHA-256 of this peer's public key (routing key)
	lastAlive time.Time
	once      sync.Once // ensures evict() runs exactly once
}

// Server is the Blind Relay core.
type Server struct {
	listener net.Listener

	mu    sync.RWMutex
	peers map[[32]byte]*peer

	pool sync.Pool
	done chan struct{}

	stopOnce sync.Once      // protects against double-close of 'done'
	wg       sync.WaitGroup // tracks all background goroutines
}

// New returns a new Blind Relay server.
func New() *Server {
	return &Server{
		peers: make(map[[32]byte]*peer, 128),
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, outerFrameSize)
				return &b
			},
		},
		done: make(chan struct{}),
	}
}

// Run starts the server and blocks until Stop() is called.
func (s *Server) Run(addr string) error {
	// Enforce strict RAM-only policy from the very beginning.
	log.SetOutput(io.Discard)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("relay: listen %s: %w", addr, err)
	}
	s.listener = ln

	// Informational startup message (acceptable for interactive use).
	// In strict daemon environments this may be captured by journald.
	fmt.Printf("[road-1337] Blind Relay started on %s\n", addr)
	fmt.Println("   Zero-trust • RAM-only • No logging • No plaintext")

	// Start background maintenance goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sweepLoop()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				continue
			}
		}

		if s.isFull() {
			conn.Close()
			continue
		}

		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// Stop performs a clean shutdown. Safe to call multiple times.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)

		if s.listener != nil {
			s.listener.Close()
		}

		// Close all active peer connections
		s.mu.Lock()
		for _, p := range s.peers {
			p.conn.Close()
		}
		s.mu.Unlock()

		// Wait for all goroutines (handleConn + sweepLoop) to exit cleanly
		s.wg.Wait()
	})
}

// ── Connection lifecycle ───────────────────────────────────────────────────

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()

	p, err := s.doHandshake(conn)
	if err != nil {
		conn.Close()
		return
	}

	s.register(p)
	defer s.evict(p)

	s.relayLoop(p)
}

func (s *Server) doHandshake(conn net.Conn) (*peer, error) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	buf := make([]byte, protocol.HandshakePayloadSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	hs, err := protocol.DecodeHandshake(buf)
	if err != nil {
		return nil, err
	}

	if hs.Version != protocol.Version {
		return nil, fmt.Errorf("protocol version mismatch: got %d, want %d", hs.Version, protocol.Version)
	}

	keyHash := sha256.Sum256(hs.SenderPubKey[:])

	return &peer{
		conn:      conn,
		keyHash:   keyHash,
		lastAlive: time.Now(),
	}, nil
}

func (s *Server) register(p *peer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if old, exists := s.peers[p.keyHash]; exists {
		old.conn.Close()
	}
	s.peers[p.keyHash] = p
}

func (s *Server) evict(p *peer) {
	p.once.Do(func() {
		p.conn.Close()

		s.mu.Lock()
		if cur, ok := s.peers[p.keyHash]; ok && cur == p {
			delete(s.peers, p.keyHash)
		}
		s.mu.Unlock()
	})
}

func (s *Server) relayLoop(p *peer) {
	bufPtr := s.pool.Get().(*[]byte)
	buf := (*bufPtr)[:outerFrameSize]

	defer func() {
		clear(buf)
		s.pool.Put(bufPtr)
	}()

	for {
		p.conn.SetDeadline(time.Now().Add(heartbeatTimeout))

		if _, err := io.ReadFull(p.conn, buf); err != nil {
			return
		}

		p.lastAlive = time.Now()

		var recipientHash [32]byte
		copy(recipientHash[:], buf[:recipientHashSize])
		packet := buf[recipientHashSize:]

		s.mu.RLock()
		recipient, found := s.peers[recipientHash]
		s.mu.RUnlock()

		if !found {
			clear(buf)
			continue
		}

		recipient.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := recipient.conn.Write(packet); err != nil {
			go s.evict(recipient)
		}

		clear(buf) // Burn-on-Read
	}
}

// ── Background maintenance ─────────────────────────────────────────────────

func (s *Server) sweepLoop() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.sweepStale()
		}
	}
}

func (s *Server) sweepStale() {
	s.mu.RLock()
	stale := make([]*peer, 0, 16)
	now := time.Now()

	for _, p := range s.peers {
		if now.Sub(p.lastAlive) > heartbeatTimeout {
			stale = append(stale, p)
		}
	}
	s.mu.RUnlock()

	for _, p := range stale {
		s.evict(p)
	}
}

func (s *Server) isFull() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers) >= maxPeers
}

func (s *Server) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

// Snapshot returns a sanitized view of the routing table for debugging.
func (s *Server) Snapshot() []PeerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]PeerInfo, 0, len(s.peers))
	for hash, p := range s.peers {
		out = append(out, PeerInfo{
			KeyHashHex: hex.EncodeToString(hash[:6]),
			RemoteAddr: p.conn.RemoteAddr().String(),
			LastAlive:  p.lastAlive,
		})
	}
	return out
}

type PeerInfo struct {
	KeyHashHex string
	RemoteAddr string
	LastAlive  time.Time
}
