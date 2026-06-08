// Package onboard handles first-run detection and the interactive setup guide.
//
// On first launch (no private key on disk), road-1337 runs a bilingual
// onboarding wizard that explains the security model, operational security
// recommendations, and generates the first keypair automatically.
//
// The sentinel file (~/.config/road-1337/setup_done) tracks completion.
// Deleting it re-runs the wizard without destroying the key.
package onboard

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const sentinelFile = "setup_done"

// IsFirstRun returns true if the onboarding wizard has not been completed yet.
// Checks for the sentinel file in the road-1337 config directory.
func IsFirstRun() bool {
	path, err := sentinelPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return os.IsNotExist(err)
}

// MarkDone writes the sentinel file so the wizard is not shown again.
func MarkDone() {
	path, err := sentinelPath()
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("1"), 0o600)
}

// Run presents the bilingual onboarding guide and returns when the user
// has read through it and pressed Enter. It does NOT generate keys;
// the caller (main) handles key generation after this returns.
func Run() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("  road-1337 — First Launch Setup")
	fmt.Println()
	fmt.Println("  Select language / Выберите язык:")
	fmt.Println()
	fmt.Println("    1  English")
	fmt.Println("    2  Русский")
	fmt.Println()
	fmt.Print("  > ")

	line, _ := reader.ReadString('\n')
	choice := strings.TrimSpace(line)

	fmt.Println()

	switch choice {
	case "2":
		printGuideRU(reader)
	default:
		printGuideEN(reader)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// English guide
// ─────────────────────────────────────────────────────────────────────────────

func printGuideEN(r *bufio.Reader) {
	banner := `
  ╔══════════════════════════════════════════════════════════════════════╗
  ║           road-1337 · Security Guide & First-Run Setup              ║
  ╚══════════════════════════════════════════════════════════════════════╝`
	fmt.Println(banner)
	fmt.Println()

	sections := []string{
		`  ── What is road-1337? ─────────────────────────────────────────────────

  road-1337 is an end-to-end encrypted (E2EE) terminal messenger
  built on a "Blind Relay" architecture.

  The relay server forwards encrypted packets between peers.
  It sees ONLY encrypted noise — never your messages, never your keys.
  There is no central authority. There is no account. There is no database.`,

		`  ── How does anonymity work? ────────────────────────────────────────────

  1. CRYPTOGRAPHY
     • X25519 Elliptic-Curve Diffie-Hellman — key exchange.
     • HKDF-SHA256 — derives a session key from the shared DH secret.
     • ChaCha20-Poly1305 AEAD — encrypts every packet with authentication.
     • All packets are padded to exactly 4096 bytes — DPI cannot fingerprint
       your traffic by size.

  2. BLIND RELAY
     • The relay routes packets by SHA-256(recipientPublicKey).
     • It never stores anything. RAM only. Logs disabled.
     • Buffers are zeroed (clear()) after every forward — cold-boot safe.

  3. OUT-OF-BAND KEY EXCHANGE
     • You share your public key with your peer outside road-1337
       (Signal, in person, paper, etc.)
     • The relay never participates in the key exchange.
     • Man-in-the-Middle is impossible if you verify keys out-of-band.`,

		`  ── Operational Security (OpSec) — READ THIS ────────────────────────────

  ⚠  road-1337 protects your MESSAGES in transit.
     It does NOT protect your IDENTITY or your DEVICE.

  To maximize anonymity, combine road-1337 with:

  1. FULL-DISK ENCRYPTION
     macOS  → enable FileVault  (System Settings → Privacy & Security)
     Windows → enable BitLocker (Control Panel → BitLocker)
     Linux  → LUKS at install time

  2. WRITE DOWN YOUR PRIVATE KEY
     After setup, your public key is printed to the screen.
     Your PRIVATE key lives in:
       Linux/macOS  → ~/.config/road-1337/private.key
       Windows      → %APPDATA%\road-1337\private.key

     WRITE THE PRIVATE KEY ON PAPER AND STORE IT SAFELY.
     If your disk fails or you change devices, this is the ONLY way
     to restore your identity. There is no recovery service.

  3. NETWORK LAYER
     road-1337 encrypts content, not metadata (IP addresses).
     For IP anonymity, tunnel through:
       • Tor (torsocks road-1337 ...)
       • VLESS/Reality proxy
       • A trusted VPN

  4. VERIFY KEYS IN PERSON (or via another secure channel)
     If you cannot verify your peer's public key out-of-band,
     an attacker could impersonate them. Always verify before chatting.

  5. /EXIT ON EVERY SESSION
     Typing /exit zeroes session keys in RAM. Ctrl+C also zeroes.
     Never just close the terminal without exiting properly.`,

		`  ── Disclaimer ──────────────────────────────────────────────────────────

  road-1337 is open-source software provided AS IS.

  USE AT YOUR OWN RISK. The developer makes NO GUARANTEE of:
    • Complete anonymity in all threat models.
    • Resistance to nation-state-level adversaries.
    • Bug-free operation in all environments.

  You are responsible for your own operational security.
  If you are operating under a high-risk threat model, consult a
  professional security researcher before relying on this tool.`,
	}

	for i, section := range sections {
		fmt.Println(section)
		fmt.Println()
		fmt.Printf("  [%d/%d] Press Enter to continue...", i+1, len(sections))
		r.ReadString('\n')
		fmt.Println()
	}

	fmt.Println("  ── Setup ───────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  A new X25519 keypair will now be generated for you.")
	fmt.Println("  Your private key will be saved with 0600 permissions (owner only).")
	fmt.Println()
	fmt.Println("  After generation, share your PUBLIC KEY with your peer")
	fmt.Println("  via a secure out-of-band channel.")
	fmt.Println()
	fmt.Print("  Press Enter to generate your keypair...")
	r.ReadString('\n')
}

// ─────────────────────────────────────────────────────────────────────────────
// Russian guide
// ─────────────────────────────────────────────────────────────────────────────

func printGuideRU(r *bufio.Reader) {
	banner := `
  ╔══════════════════════════════════════════════════════════════════════╗
  ║        road-1337 · Руководство по безопасности и первый запуск       ║
  ╚══════════════════════════════════════════════════════════════════════╝`
	fmt.Println(banner)
	fmt.Println()

	sections := []string{
		`  ── Что такое road-1337? ────────────────────────────────────────────────

  road-1337 — это консольный мессенджер со сквозным шифрованием (E2EE)
  на базе архитектуры "Слепой ретранслятор" (Blind Relay).

  Сервер пересылает зашифрованные пакеты между участниками.
  Он видит ТОЛЬКО зашифрованный шум — никогда не видит сообщения и ключи.
  Нет центрального сервера. Нет аккаунта. Нет базы данных.`,

		`  ── Как работает анонимность? ───────────────────────────────────────────

  1. КРИПТОГРАФИЯ
     • X25519 — обмен ключами на эллиптических кривых.
     • HKDF-SHA256 — деривация сессионного ключа из DH-секрета.
     • ChaCha20-Poly1305 AEAD — шифрование каждого пакета с аутентификацией.
     • Все пакеты выравнивются до ровно 4096 байт — DPI не видит размер сообщения.

  2. СЛЕПОЙ РЕТРАНСЛЯТОР
     • Сервер маршрутизирует по SHA-256(publicKey получателя).
     • Ничего не хранит. Только RAM. Логи отключены.
     • Буферы зануляются (clear()) после каждой пересылки — защита от cold-boot.

  3. ВНЕПОЛОСНЫЙ ОБМЕН КЛЮЧАМИ
     • Ты передаёшь публичный ключ собеседнику ВНЕ road-1337
       (через Signal, лично, на бумаге, и т.д.)
     • Сервер не участвует в обмене ключами.
     • Атака Man-in-the-Middle невозможна при правильном обмене ключами.`,

		`  ── Операционная безопасность (OpSec) — ПРОЧИТАЙ ───────────────────────

  ⚠  road-1337 защищает СОДЕРЖИМОЕ твоих сообщений при передаче.
     Он НЕ защищает твою ЛИЧНОСТЬ и твоё УСТРОЙСТВО.

  Для максимальной анонимности сочетай road-1337 с:

  1. ПОЛНОДИСКОВОЕ ШИФРОВАНИЕ
     macOS   → включи FileVault  (Системные настройки → Конфиденциальность)
     Windows → включи BitLocker  (Панель управления → BitLocker)
     Linux   → LUKS при установке

  2. ЗАПИШИ ПРИВАТНЫЙ КЛЮЧ НА БУМАГУ
     После генерации на экране появится твой ПУБЛИЧНЫЙ ключ.
     ПРИВАТНЫЙ ключ хранится в:
       Linux/macOS  → ~/.config/road-1337/private.key
       Windows      → %APPDATA%\road-1337\private.key

     ЗАПИШИ ПРИВАТНЫЙ КЛЮЧ НА БУМАГУ И ХРАНИ В НАДЁЖНОМ МЕСТЕ.
     Если диск сломается или сменишь устройство — это ЕДИНСТВЕННЫЙ
     способ восстановить свою идентичность. Сервиса восстановления нет.

  3. СЕТЕВОЙ УРОВЕНЬ
     road-1337 шифрует содержимое, но не метаданные (IP-адреса).
     Для анонимности на уровне сети используй туннели:
       • Tor (torsocks road-1337 ...)
       • VLESS/Reality прокси
       • Доверенный VPN

  4. ВЕРИФИЦИРУЙ КЛЮЧИ ЛИЧНО (или через другой защищённый канал)
     Если ты не можешь проверить публичный ключ собеседника вне системы,
     злоумышленник может выдать себя за него. Всегда верифицируй перед общением.

  5. /EXIT В КОНЦЕ КАЖДОЙ СЕССИИ
     Команда /exit зануляет сессионные ключи в RAM. Ctrl+C тоже зануляет.
     Никогда не закрывай терминал без явного выхода из сессии.`,

		`  ── Отказ от ответственности ────────────────────────────────────────────

  road-1337 — программное обеспечение с открытым исходным кодом,
  предоставляемое "КАК ЕСТЬ" (AS IS).

  ИСПОЛЬЗОВАТЬ НА СВОЙ СТРАХ И РИСК. Разработчик НЕ ГАРАНТИРУЕТ:
    • Полную анонимность во всех моделях угроз.
    • Защиту от атак на уровне государственных структур.
    • Безошибочную работу во всех окружениях.

  Ты несёшь ответственность за собственную операционную безопасность.
  При работе в условиях высокого уровня угроз — проконсультируйся
  с профессиональным исследователем безопасности.`,
	}

	for i, section := range sections {
		fmt.Println(section)
		fmt.Println()
		fmt.Printf("  [%d/%d] Нажми Enter для продолжения...", i+1, len(sections))
		r.ReadString('\n')
		fmt.Println()
	}

	fmt.Println("  ── Настройка ───────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Сейчас будет сгенерирована новая пара ключей X25519.")
	fmt.Println("  Приватный ключ будет сохранён с правами 0600 (только владелец).")
	fmt.Println()
	fmt.Println("  После генерации передай ПУБЛИЧНЫЙ ключ собеседнику")
	fmt.Println("  через безопасный внеполосный канал.")
	fmt.Println()
	fmt.Print("  Нажми Enter для генерации ключевой пары...")
	r.ReadString('\n')
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func sentinelPath() (string, error) {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
		if base == "" {
			return "", fmt.Errorf("APPDATA not set")
		}
		return filepath.Join(base, "road-1337", sentinelFile), nil
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".config", "road-1337", sentinelFile), nil
	}
}
