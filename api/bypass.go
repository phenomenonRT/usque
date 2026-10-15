package api

import (
	"crypto/tls"
	"math/rand/v2"
	"net"
	"time"
)

// TLSFragmentConfig управляет разбиением TLS ClientHello на несколько TCP-сегментов.
//
// Это клиентский обход DPI: системы вроде ТСПУ сопоставляют шаблон рукопожатия
// (в первую очередь SNI) в пределах одного сегмента/пакета. Если разорвать
// ClientHello в середине имени сервера, проверяющее устройство не видит цельный
// шаблон, а удалённый сервер без проблем собирает поток TCP.
//
// Нулевая конфигурация выключена. Auto включает разбиение по имени сервера,
// Sizes задаёт сегменты явно и имеет приоритет.
type TLSFragmentConfig struct {
	// Auto — рвать ClientHello внутри имени сервера (SNI).
	Auto bool
	// Sizes — явные размеры первых сегментов в байтах.
	Sizes []int
	// Delay — пауза между сегментами.
	Delay time.Duration
	// Jitter — максимальное случайное смещение (в байтах, ±) точек разрыва.
	// Без него точка разрыва постоянна, а значит сама является признаком.
	Jitter int
}

// DefaultTLSFragmentConfig возвращает конфигурацию с автоматическим разбиением
// по SNI.
func DefaultTLSFragmentConfig() *TLSFragmentConfig {
	return &TLSFragmentConfig{Auto: true}
}

// Enabled сообщает, есть ли смысл заворачивать соединение во фрагментатор.
func (c *TLSFragmentConfig) Enabled() bool {
	return c != nil && (c.Auto || len(c.Sizes) > 0)
}

// TunnelCandidate — одна проверяемая комбинация «SNI + адрес сервера + транспорт».
// Клиент перебирает такие кандидаты, пока тоннель не поднимется.
type TunnelCandidate struct {
	TLSConfig *tls.Config
	Endpoint  net.Addr
	UseHTTP2  bool
	Label     string
	// InitialPacketSize, когда не ноль, задаёт размер первого QUIC-пакета для
	// этой попытки. Перебор разных значений не даёт DPI зацепиться за константу.
	InitialPacketSize uint16
	// LocalPort, когда не ноль, задаёт порт источника для QUIC-сокета
	// (некоторые DPI фильтруют по нему). Требует прав на привилегированные
	// порты; при неудаче попытка просто провалится.
	LocalPort int
}

// wrapTLSFragment оборачивает соединение так, чтобы первый Write (TLS ClientHello)
// ушёл несколькими TCP-сегментами. Если конфигурация выключена, соединение
// возвращается без изменений.
func wrapTLSFragment(conn net.Conn, cfg *TLSFragmentConfig) net.Conn {
	if !cfg.Enabled() {
		return conn
	}
	return &fragmentConn{Conn: conn, cfg: cfg}
}

// maxTLSFragmentBuffer ограничивает буфер, который fragmentConn копит в ожидании
// целой записи ClientHello. Если запись не пришла целиком, буфер сбрасывается
// как есть — лучше отправить данные без дробления, чем задержать рукопожатие.
const maxTLSFragmentBuffer = 16 * 1024

// fragmentConn — net.Conn, разбивающий начало исходящего потока на сегменты.
//
// Первый Write у TLS — целая запись ClientHello. Чтобы оборвать её в середине
// SNI, буфер копится до целой записи, затем план дробления вычисляется по
// фактическому содержимому (planFor), и данные уходят сегментами. Всё, что идёт
// после, пишется напрямую. Явно заданные Sizes применяются сразу, без ожидания
// записи.
type fragmentConn struct {
	net.Conn
	cfg *TLSFragmentConfig

	buf         []byte
	plan        []int
	planReady   bool
	passthrough bool
}

func (c *fragmentConn) Write(b []byte) (int, error) {
	if c.passthrough || !c.cfg.Enabled() {
		return c.Conn.Write(b)
	}

	if !c.planReady && len(c.cfg.Sizes) > 0 {
		c.plan = c.cfg.Sizes
		c.planReady = true
	}

	c.buf = append(c.buf, b...)

	if !c.planReady {
		total, decided, isTLS := tlsRecordTotal(c.buf)
		switch {
		case !decided:
			// Ещё не видно даже заголовка записи — ждём, но не бесконечно.
			if len(c.buf) < maxTLSFragmentBuffer {
				return len(b), nil
			}
			c.plan = nil
			c.planReady = true
		case !isTLS || total > len(c.buf):
			if isTLS && total <= maxTLSFragmentBuffer {
				return len(b), nil // ждём остаток записи
			}
			// Не TLS или запись неразумно большая — шлём как есть.
			c.plan = nil
			c.planReady = true
		default:
			c.plan = c.cfg.planFor(c.buf)
			c.planReady = true
		}
	}

	return len(b), c.flush()
}

// flush отправляет накопленное: сначала сегменты по плану, затем остаток целиком.
// После этого соединение работает как обычное.
func (c *fragmentConn) flush() error {
	defer func() {
		c.buf = nil
		c.passthrough = true
	}()

	rest := c.buf
	for _, n := range c.plan {
		if n <= 0 || len(rest) == 0 {
			break
		}
		if n > len(rest) {
			n = len(rest)
		}
		if err := writeAll(c.Conn, rest[:n]); err != nil {
			return err
		}
		rest = rest[n:]
		if c.cfg.Delay > 0 {
			time.Sleep(c.cfg.Delay)
		}
	}
	if len(rest) > 0 {
		if err := writeAll(c.Conn, rest); err != nil {
			return err
		}
	}
	return nil
}

// planFor выбирает, на какие сегменты разрезать первую запись ClientHello.
// Возвращаются размеры сегментов (как у явных Sizes), а не смещения.
//
// Явные Sizes имеют приоритет. Иначе берутся две точки внутри имени сервера
// (SNI): именно его ищет DPI, и разрыв внутри имени не даёт собрать шаблон — ни
// цельного имени, ни цельного ClientHello. Если ClientHello разобрать не
// удалось, используется классический разрыв после первого байта.
func (c *TLSFragmentConfig) planFor(buf []byte) []int {
	if len(c.Sizes) > 0 {
		return c.Sizes
	}
	start, end, ok := clientHelloSNI(buf)
	if !ok || end-start < 3 {
		return []int{1}
	}

	n := end - start
	offsets := []int{start + n/3, start + 2*n/3}
	if c.Jitter > 0 {
		for i := range offsets {
			offsets[i] += rand.IntN(2*c.Jitter+1) - c.Jitter
		}
	}

	sizes := make([]int, 0, len(offsets))
	prev := 0
	for _, off := range offsets {
		if off <= start || off >= end || off <= prev {
			continue
		}
		sizes = append(sizes, off-prev)
		prev = off
	}
	if len(sizes) == 0 {
		return []int{1}
	}
	return sizes
}

// tlsRecordTotal разбирает заголовок первой TLS-записи.
//
// decided=false означает, что байтов ещё мало для решения. isTLS=false — что
// поток не похож на TLS-рукопожатие. В противном случае total — полный размер
// записи (заголовок + полезная нагрузка).
func tlsRecordTotal(buf []byte) (total int, decided bool, isTLS bool) {
	if len(buf) < 5 {
		return 0, false, false
	}
	if buf[0] != 0x16 || buf[1] != 0x03 { // not a handshake record
		return 0, true, false
	}
	n := int(buf[3])<<8 | int(buf[4])
	if n <= 0 || n > 16*1024 {
		return 0, true, false
	}
	return 5 + n, true, true
}

// clientHelloSNI находит границы имени сервера внутри записи TLS ClientHello.
// start/end — абсолютные смещения в buf, end не включается.
func clientHelloSNI(buf []byte) (start, end int, ok bool) {
	if len(buf) < 9 || buf[0] != 0x16 || buf[5] != 0x01 {
		return 0, 0, false
	}
	p := 9 // record(5) + handshake header(4)

	// client_version(2) + random(32)
	if p+34 > len(buf) {
		return 0, 0, false
	}
	p += 34

	// session_id
	if p+1 > len(buf) {
		return 0, 0, false
	}
	sidLen := int(buf[p])
	p++
	if p+sidLen > len(buf) {
		return 0, 0, false
	}
	p += sidLen

	// cipher_suites
	if p+2 > len(buf) {
		return 0, 0, false
	}
	csLen := int(buf[p])<<8 | int(buf[p+1])
	p += 2
	if p+csLen > len(buf) {
		return 0, 0, false
	}
	p += csLen

	// compression_methods
	if p+1 > len(buf) {
		return 0, 0, false
	}
	cmLen := int(buf[p])
	p++
	if p+cmLen > len(buf) {
		return 0, 0, false
	}
	p += cmLen

	// extensions
	if p+2 > len(buf) {
		return 0, 0, false
	}
	extLen := int(buf[p])<<8 | int(buf[p+1])
	p += 2
	if p+extLen > len(buf) {
		return 0, 0, false
	}
	extEnd := p + extLen
	for p+4 <= extEnd {
		etype := int(buf[p])<<8 | int(buf[p+1])
		elen := int(buf[p+2])<<8 | int(buf[p+3])
		p += 4
		if p+elen > extEnd {
			return 0, 0, false
		}
		if etype != 0 { // server_name
			p += elen
			continue
		}
		// server_name: list_len(2), name_type(1), host_len(2), host
		if elen < 5 || p+5 > extEnd {
			return 0, 0, false
		}
		hostLen := int(buf[p+3])<<8 | int(buf[p+4])
		if p+5+hostLen > extEnd {
			return 0, 0, false
		}
		return p + 5, p + 5 + hostLen, hostLen > 0
	}
	return 0, 0, false
}

// writeAll пишет весь буфер, повторяя Write при короткой записи.
func writeAll(w net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return net.ErrClosed
		}
		b = b[n:]
	}
	return nil
}
