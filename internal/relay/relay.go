// Package relay implements the road-1337 Blind Relay server.
//
// Design: deliberately "dumb." Routes opaque encrypted packets between peers
// keyed by SHA-256(senderPublicKey). Never decrypts, never logs to disk,
// retains nothing after forwarding each packet.
//
// Security invariants — never violate:
//
// Zero disk I/O : log.SetOutput(io.Discard) at startup.
// Burn-on-Read : relay buffers zeroed via clear() after every Write.
// Bounded memory : sync.Pool recycles fixed buffers; GC stays quiet.
// Resilient evict : background sweeper purges peers that miss heartbeats.
// Race-free fields : s.listener protected by listenerMu; s.done closed once.
// Graceful shutdown: sync.WaitGroup joins every goroutine before returning.
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

	handshakeTimeout = 20 * time.Second // Increased slightly for stability
	heartbeatTimeout = 45 * time.Second
	writeTimeout     = 10 * time.Second
	maxPeers         = 2048
	sweepInterval    = 15 * time.Second
)

// peer represents one active TCP connection in the routing table.
type peer struct {
	conn      net.Conn
	keyHash   [32]byte
	lastAlive time.Time
	once      sync.Once
}

// Server is the Blind Relay core.
type Server struct {
	// listenerMu protects listener so Stop() can safely close it
	// while Run() writes it before the accept loop starts.
	listenerMu sync.Mutex
	listener   net.Listener

	// mu guards the peers map.
	mu    sync.RWMutex
	peers map[[32]byte]*peer

	// pool recycles outerFrameSize-byte relay buffers.
	pool sync.Pool

	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New constructs a Server ready for use.
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

// Run binds to addr and blocks until Stop() is called.
func (s *Server) Run(addr string) error {
	log.SetOutput(io.Discard)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("relay: listen %s: %w", addr, err)
	}

	s.listenerMu.Lock()
	s.listener = ln
	s.listenerMu.Unlock()

	fmt.Printf("[road-1337] Blind Relay started on %s\n", addr)
	fmt.Println(" Zero-trust • RAM-only • No logging • No plaintext")

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

// Stop performs a clean shutdown.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)

		s.listenerMu.Lock()
		if s.listener != nil {
			s.listener.Close()
		}
		s.listenerMu.Unlock()

		s.mu.Lock()
		for _, p := range s.peers {
			p.conn.Close()
		}
		s.mu.Unlock()

		s.wg.Wait()
	})
}

// --- connection lifecycle ---

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

// doHandshake includes protection against Slowloris attacks.
func (s *Server) doHandshake(conn net.Conn) (*peer, error) {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	buf := make([]byte, protocol.HandshakePayloadSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("handshake read: %w", err)
	}

	hs, err := protocol.DecodeHandshake(buf)
	if err != nil {
		return nil, fmt.Errorf("handshake decode: %w", err)
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
		if err := p.conn.SetDeadline(time.Now().Add(heartbeatTimeout)); err != nil {
			return
		}

		if _, err := io.ReadFull(p.conn, buf); err != nil {
			return
		}

		p.lastAlive = time.Now()

		var recipientHash [32]byte
		copy(recipientHash[:], buf[:recipientHashSize])
		encryptedPacket := buf[recipientHashSize:]

		s.mu.RLock()
		recipient, found := s.peers[recipientHash]
		s.mu.RUnlock()

		if !found {
			clear(buf)
			continue
		}

		if err := recipient.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			go s.evict(recipient)
			clear(buf)
			continue
		}

		if _, err := recipient.conn.Write(encryptedPacket); err != nil {
			go s.evict(recipient)
		}

		clear(buf) // Burn-on-Read
	}
}

// --- background eviction ---

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
	now := time.Now()
	s.mu.RLock()
	stale := make([]*peer, 0, 16) // pre-allocated
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
