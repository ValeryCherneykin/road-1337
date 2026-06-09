// Package client implements the road-1337 E2EE network session.
//
// Session lifecycle:
//
//  1. NewSession(kp, peerPubKey) — allocate channels and state.
//  2. Run(serverAddr) — start TUI, then connect() in background goroutine.
//  3. connect() — ECDH key derivation → TCP dial → handshake → spawn loops.
//  4. sendLoop / recvLoop / pingLoop — concurrent network I/O.
//  5. Zeroize() — idempotent teardown: key wipe, conn close, file cleanup.
//
// File transfer uses a "byte-count completion" model:
// The sender includes TotalSize in the FileHeader.
// The receiver closes the file when receivedBytes == TotalSize.
// No TypeFileEOF packet is needed, reducing protocol surface area.
//
// Race-free design:
//   - s.conn and s.cipherSess are written once in connect() and read-only
//     after that in sendLoop/recvLoop — no lock needed for the read path.
//   - s.stateMu is used in sendPacket() only to guard nil checks during
//     the brief window between connect() failure and Zeroize().
//   - Zeroize() uses sync.Once; all callers are safe to invoke concurrently.
package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ValeryCherneykin/road-1337/internal/crypto"
	"github.com/ValeryCherneykin/road-1337/internal/protocol"
	"github.com/ValeryCherneykin/road-1337/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
)

const (
	dialTimeout   = 10 * time.Second
	pingInterval  = 10 * time.Second
	recvDeadline  = 45 * time.Second // must exceed pingInterval
	writeDeadline = 10 * time.Second

	// outerFrameSize: 32-byte recipient hash + encrypted application packet.
	outerFrameSize = 32 + crypto.PacketSize
)

// fileTransfer tracks one active incoming file transfer.
type fileTransfer struct {
	fh            protocol.FileHeaderPayload
	file          *os.File
	outPath       string // final path on disk (used in the completion message)
	receivedBytes uint64 // bytes received so far
	mu            sync.Mutex
	done          bool
}

// Session owns the full lifecycle of one E2EE relay connection.
type Session struct {
	kp          *crypto.KeyPair
	peerPubKey  []byte
	peerKeyHash [32]byte

	// conn and cipherSess are nil until connect() succeeds,
	// then read-only for the lifetime of the loops.
	conn       net.Conn
	cipherSess *crypto.Session

	// stateMu guards nil checks on conn/cipherSess in sendPacket().
	// Held read-only during normal operation; write-locked only in Zeroize().
	stateMu sync.RWMutex

	outgoing chan string  // TUI commands → sendLoop
	incoming chan tea.Msg // network events → TUI (buffered to absorb startup burst)

	transfersMu sync.Mutex
	transfers   map[uint32]*fileTransfer

	done     chan struct{}
	doneOnce sync.Once
}

// NewSession allocates a Session without opening any connections.
func NewSession(kp *crypto.KeyPair, peerPubKey []byte) *Session {
	peerCopy := make([]byte, len(peerPubKey))
	copy(peerCopy, peerPubKey)

	return &Session{
		kp:          kp,
		peerPubKey:  peerCopy,
		peerKeyHash: sha256.Sum256(peerCopy),
		outgoing:    make(chan string, 32),
		incoming:    make(chan tea.Msg, 64),
		transfers:   make(map[uint32]*fileTransfer),
		done:        make(chan struct{}),
	}
}

// Run starts the Bubble Tea TUI and initiates the network connection
// in a background goroutine. Blocks until the TUI exits.
func (s *Session) Run(serverAddr string) error {
	defer s.Zeroize()

	model := tui.New(peerDisplayKey(s.peerPubKey), s.outgoing, s.incoming, crypto.CheckFirstRun())
	p := tea.NewProgram(model, tea.WithAltScreen())

	// connect() runs in background; it writes to the buffered incoming channel
	// so it never blocks waiting for the TUI event loop to start.
	go s.connect(serverAddr)

	_, err := p.Run()

	return err
}

// connect performs ECDH, TCP dial, and protocol handshake, then starts the I/O loops.
// On any error it sends PeerDisconnectedMsg so the TUI can quit cleanly.
func (s *Session) connect(serverAddr string) {
	s.incoming <- tui.StatusMsg{Text: "Connecting..."}

	// ECDH key derivation.
	sharedKey, err := s.kp.ECDH(s.peerPubKey)
	if err != nil {
		s.abortWithMsg("ECDH failed: " + err.Error())
		return
	}

	cs, err := crypto.NewSession(sharedKey)
	clear(sharedKey)
	if err != nil {
		s.abortWithMsg("cipher init failed: " + err.Error())
		return
	}

	// TCP connection. "tcp4" forces IPv4; avoids Windows IPv6 resolution delays.
	conn, err := net.DialTimeout("tcp4", serverAddr, dialTimeout)
	if err != nil {
		cs.Zeroize()
		s.abortWithMsg("dial failed: " + err.Error())
		return
	}

	// Protocol handshake — the only unencrypted bytes in the session.
	myPubBytes := s.kp.PublicKeyBytes()
	var myPubKey [32]byte
	copy(myPubKey[:], myPubBytes)

	hs := protocol.HandshakePayload{
		Version:          protocol.Version,
		SenderPubKey:     myPubKey,
		RecipientKeyHash: s.peerKeyHash,
	}
	if _, err := conn.Write(protocol.EncodeHandshake(hs)); err != nil {
		_ = conn.Close()
		cs.Zeroize()
		s.abortWithMsg("handshake failed: " + err.Error())
		return
	}

	// Store connection state atomically before starting loops.
	s.stateMu.Lock()
	s.conn = conn
	s.cipherSess = cs
	s.stateMu.Unlock()

	s.incoming <- tui.StatusMsg{Text: "SECURE"}

	go s.sendLoop()
	go s.recvLoop()
	go s.pingLoop()
}

func (s *Session) abortWithMsg(msg string) {
	s.incoming <- tui.IncomingTextMsg{Text: "⚠  " + msg}
	s.incoming <- tui.PeerDisconnectedMsg{}
	s.Zeroize()
}

// Zeroize zeroes all key material, closes the connection, and cleans up
// any open file transfers. Idempotent — safe from multiple goroutines.
func (s *Session) Zeroize() {
	s.doneOnce.Do(func() {
		close(s.done)

		s.stateMu.Lock()
		if s.cipherSess != nil {
			s.cipherSess.Zeroize()
			s.cipherSess = nil
		}
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
		}
		s.stateMu.Unlock()

		clear(s.peerPubKey)

		s.transfersMu.Lock()
		for _, ft := range s.transfers {
			if ft.file != nil {
				_ = ft.file.Close()
			}
		}
		s.transfers = make(map[uint32]*fileTransfer)
		s.transfersMu.Unlock()
	})
}

// --- I/O goroutines ---

// sendLoop reads user commands from outgoing and dispatches them.
// It is the sole writer to s.conn for outbound application traffic.
func (s *Session) sendLoop() {
	for {
		select {
		case <-s.done:
			return
		case text := <-s.outgoing:
			switch {
			case text == "/exit":
				_ = s.sendPacket(protocol.BuildMessage(protocol.TypeDisconnect, nil))
				s.incoming <- tui.PeerDisconnectedMsg{}
				s.Zeroize()
				return

			case strings.HasPrefix(text, "/file "):
				path := strings.TrimSpace(strings.TrimPrefix(text, "/file "))
				go s.sendFile(path)

			default:
				if err := s.sendPacket(
					protocol.BuildMessage(protocol.TypeMessage, []byte(text)),
				); err != nil {
					s.incoming <- tui.IncomingTextMsg{Text: "⚠  send error: " + err.Error()}
				}
			}
		}
	}
}

// recvLoop reads encrypted packets from the relay and dispatches decrypted events.
func (s *Session) recvLoop() {
	packet := make([]byte, crypto.PacketSize)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		s.stateMu.RLock()
		conn := s.conn
		cs := s.cipherSess
		s.stateMu.RUnlock()

		if conn == nil || cs == nil {
			return
		}

		if err := conn.SetReadDeadline(time.Now().Add(recvDeadline)); err != nil {
			log.Printf("failed to set deadline: %v", err)
		}
		if _, err := io.ReadFull(conn, packet); err != nil {
			select {
			case <-s.done:
				return
			default:
				s.incoming <- tui.PeerDisconnectedMsg{}
				s.Zeroize()
				return
			}
		}

		plain, err := cs.Open(packet)
		if err != nil {
			s.incoming <- tui.IncomingTextMsg{Text: "⚠  decryption failed — packet discarded"}
			continue
		}

		hdr, body, err := protocol.DecodeHeader(plain)
		if err != nil {
			continue
		}
		s.dispatch(hdr, body)
	}
}

// dispatch routes a decrypted, parsed packet to its handler.
func (s *Session) dispatch(hdr protocol.WireHeader, body []byte) {
	switch hdr.Type {
	case protocol.TypeMessage:
		s.incoming <- tui.IncomingTextMsg{Text: string(body)}

	case protocol.TypeFileHeader:
		fh, err := protocol.DecodeFileHeader(body)
		if err != nil {
			s.incoming <- tui.IncomingTextMsg{Text: "⚠  invalid file header"}
			return
		}
		s.recvFile(fh)

	case protocol.TypeFileChunk:
		s.appendChunk(hdr.FileID, body)

	case protocol.TypePing:
		_ = s.sendPacket(protocol.BuildMessage(protocol.TypePong, nil))

	case protocol.TypePong:
		// heartbeat acknowledged

	case protocol.TypeDisconnect:
		s.incoming <- tui.PeerDisconnectedMsg{}
		s.Zeroize()
	}
}

// pingLoop sends TypePing every pingInterval to keep the relay slot alive.
func (s *Session) pingLoop() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.sendPacket(protocol.BuildMessage(protocol.TypePing, nil)); err != nil {
				return
			}
		}
	}
}

// --- File transfer: send ---

// sendFile reads path and transmits it as 128 KB encrypted logical chunks.
// Each logical chunk is sub-split into PacketSize sub-packets on the wire.
func (s *Session) sendFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		s.incoming <- tui.IncomingTextMsg{Text: "⚠  open: " + err.Error()}
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("error closing file: %v", err)
		}
	}()

	info, err := f.Stat()
	if err != nil {
		s.incoming <- tui.IncomingTextMsg{Text: "⚠  stat: " + err.Error()}
		return
	}

	// Cryptographically random FileID prevents chunk mis-routing across transfers.
	var fileID uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &fileID); err != nil {
		fileID = uint32(time.Now().UnixNano()) // acceptable fallback
	}

	totalSize := uint64(info.Size())
	totalChunks := uint32(1)
	if totalSize > 0 {
		totalChunks = uint32((int64(totalSize) + int64(protocol.ChunkSize) - 1) / int64(protocol.ChunkSize))
	}
	filename := filepath.Base(path)

	headerBytes, err := protocol.EncodeFileHeader(protocol.FileHeaderPayload{
		Filename:    filename,
		TotalSize:   totalSize,
		TotalChunks: totalChunks,
		FileID:      fileID,
	})
	if err != nil {
		s.incoming <- tui.IncomingTextMsg{Text: "⚠  encode header: " + err.Error()}
		return
	}
	if err := s.sendPacket(protocol.BuildMessage(protocol.TypeFileHeader, headerBytes)); err != nil {
		s.incoming <- tui.IncomingTextMsg{Text: "⚠  send header: " + err.Error()}
		return
	}

	s.incoming <- tui.IncomingFileMsg{Text: filename, Meta: "Sending..."}

	chunk := make([]byte, protocol.ChunkSize)
	var chunkIdx uint32

	if totalSize == 0 {
		// Zero-byte file: send a single empty chunk so TotalChunks==1 is satisfied.
		_ = s.sendPacket(protocol.BuildFileChunk(fileID, 0, nil))
		s.incoming <- tui.IncomingFileMsg{Text: filename, Meta: "Sent ✓"}
		return
	}

	for {
		n, readErr := f.Read(chunk)
		if n > 0 {
			if err := s.sendChunkFragmented(fileID, chunkIdx, chunk[:n]); err != nil {
				s.incoming <- tui.IncomingTextMsg{
					Text: fmt.Sprintf("⚠  chunk %d aborted: %v", chunkIdx, err),
				}
				return
			}
			chunkIdx++
			pct := int(float64(chunkIdx) / float64(totalChunks) * 100)
			s.incoming <- tui.FileProgressMsg{Status: tui.RenderProgress(filename, pct)}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			s.incoming <- tui.IncomingTextMsg{Text: "⚠  read file: " + readErr.Error()}
			return
		}
	}

	s.incoming <- tui.FileProgressMsg{Status: ""}
	s.incoming <- tui.IncomingFileMsg{
		Text: filename,
		Meta: fmt.Sprintf("%d KB sent ✓", totalSize/1024),
	}
}

// sendChunkFragmented splits a >MaxPlaintextSize payload into PacketSize sub-packets.
func (s *Session) sendChunkFragmented(fileID, chunkIdx uint32, data []byte) error {
	const maxBody = crypto.MaxPlaintextSize - protocol.HeaderSize
	for len(data) > 0 {
		end := maxBody
		if end > len(data) {
			end = len(data)
		}
		payload := protocol.BuildFileChunk(fileID, chunkIdx, data[:end])
		if err := s.sendPacket(payload); err != nil {
			return err
		}
		data = data[end:]
	}
	return nil
}

// --- File transfer: receive ---

// recvFile creates the output file and registers the transfer in the registry.
// Subsequent TypeFileChunk packets are routed to appendChunk() via dispatch().
func (s *Session) recvFile(fh protocol.FileHeaderPayload) {
	savePath, err := getSavePath(fh.Filename)
	if err != nil {
		s.incoming <- tui.IncomingTextMsg{Text: "⚠  resolve save path: " + err.Error()}
		return
	}

	// Avoid silently overwriting existing files.
	if _, err := os.Stat(savePath); err == nil {
		ext := filepath.Ext(savePath)
		base := strings.TrimSuffix(filepath.Base(savePath), ext)
		dir := filepath.Dir(savePath)
		savePath = filepath.Join(dir,
			fmt.Sprintf("%s_%d%s", base, time.Now().Unix()%100000, ext))
	}

	f, err := os.OpenFile(savePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		s.incoming <- tui.IncomingTextMsg{Text: "⚠  create file: " + err.Error()}
		return
	}

	s.transfersMu.Lock()
	s.transfers[fh.FileID] = &fileTransfer{fh: fh, file: f, outPath: savePath}
	s.transfersMu.Unlock()

	s.incoming <- tui.IncomingFileMsg{Text: fh.Filename, Meta: "Receiving..."}
}

// appendChunk writes a chunk to disk and completes the transfer when TotalSize
// bytes have been received. Completion is by byte-count — no TypeFileEOF needed.
func (s *Session) appendChunk(fileID uint32, body []byte) {
	s.transfersMu.Lock()
	ft, ok := s.transfers[fileID]
	s.transfersMu.Unlock()

	if !ok || ft == nil {
		return
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	if ft.done {
		return
	}

	// Reject oversized chunks — potential memory exhaustion / attack vector.
	if len(body) > protocol.ChunkSize {
		s.incoming <- tui.IncomingTextMsg{
			Text: fmt.Sprintf("⚠  oversized chunk (%d B) — transfer aborted", len(body)),
		}
		_ = ft.file.Close()
		ft.done = true
		s.transfersMu.Lock()
		delete(s.transfers, fileID)
		s.transfersMu.Unlock()
		return
	}

	if len(body) > 0 {
		n, err := ft.file.Write(body)
		if err != nil {
			s.incoming <- tui.IncomingTextMsg{Text: "⚠  disk write: " + err.Error()}
			return
		}
		ft.receivedBytes += uint64(n)
	}

	pct := 0
	if ft.fh.TotalSize > 0 {
		pct = int(float64(ft.receivedBytes) / float64(ft.fh.TotalSize) * 100)
	}
	s.incoming <- tui.FileProgressMsg{Status: tui.RenderProgress(ft.fh.Filename, pct)}

	if ft.receivedBytes >= ft.fh.TotalSize {
		_ = ft.file.Close()
		ft.done = true

		s.transfersMu.Lock()
		delete(s.transfers, fileID)
		s.transfersMu.Unlock()

		s.incoming <- tui.FileProgressMsg{Status: ""}
		s.incoming <- tui.IncomingFileMsg{
			Text: ft.fh.Filename,
			Meta: fmt.Sprintf("saved → %s ✓", ft.outPath),
		}
	}
}

// --- wire I/O ---

// sendPacket encrypts payload and writes the relay outer frame:
//
//	[recipient_key_hash: 32 B][encrypted_packet: PacketSize B]
func (s *Session) sendPacket(payload []byte) error {
	s.stateMu.RLock()
	cs := s.cipherSess
	conn := s.conn
	s.stateMu.RUnlock()

	select {
	case <-s.done:
		return fmt.Errorf("session closed")
	default:
	}

	if cs == nil || conn == nil {
		return fmt.Errorf("session not ready")
	}

	enc, err := cs.Seal(payload)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	frame := make([]byte, outerFrameSize)
	copy(frame[:32], s.peerKeyHash[:])
	copy(frame[32:], enc)

	if err := conn.SetWriteDeadline(time.Now().Add(writeDeadline)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	_, err = conn.Write(frame)
	return err
}

// --- helpers ---

// getSavePath returns ~/Downloads/road-1337/<filename>, creating directories as needed.
// Cross-platform: uses os.UserHomeDir() so it works on Linux, macOS, and Windows.
func getSavePath(filename string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Downloads", "road-1337")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	safe := filepath.Base(filename)
	if safe == "." || safe == "/" || safe == `\` || safe == "" {
		safe = "unnamed_file"
	}
	return filepath.Join(dir, safe), nil
}

func peerDisplayKey(pubKey []byte) string {
	if len(pubKey) == 0 {
		return "unknown"
	}
	enc := crypto.EncodeBase58(pubKey)
	if len(enc) > 24 {
		return enc[:24] + "…"
	}
	return enc
}
