package api

import (
	"crypto/tls"
	"net"
	"time"
)

// TLSFragmentConfig управляет разбиением TLS ClientHello на несколько TCP-сегментов.
//
// Это клиентский обход DPI: системы вроде ТСПУ сопоставляют шаблон рукопожатия
// (в первую очередь SNI) в пределах одного сегмента/пакета. Если разорвать
// первые байты ClientHello на отдельные сегменты, проверяющее устройство не
// видит цельный шаблон, а удалённый сервер без проблем собирает поток TCP.
//
// Sizes — размеры первых сегментов в байтах. Например, {1} означает «1 байт,
// затем всё остальное» (классический split). {1, 1, 1} — три первых сегмента
// по одному байту, затем остаток. Delay — пауза между сегментами.
type TLSFragmentConfig struct {
	Sizes []int
	Delay time.Duration
}

// DefaultTLSFragmentConfig возвращает безопасный по умолчанию вариант: первый
// сегмент 1 байт, затем остальное.
func DefaultTLSFragmentConfig() *TLSFragmentConfig {
	return &TLSFragmentConfig{Sizes: []int{1}}
}

// Enabled сообщает, есть ли смысл заворачивать соединение во фрагментатор.
func (c *TLSFragmentConfig) Enabled() bool {
	return c != nil && len(c.Sizes) > 0
}

// TunnelCandidate — одна проверяемая комбинация «SNI + адрес сервера + транспорт».
// Клиент перебирает такие кандидаты, пока тоннель не поднимется.
type TunnelCandidate struct {
	TLSConfig *tls.Config
	Endpoint  net.Addr
	UseHTTP2  bool
	Label     string
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

// fragmentConn — net.Conn, разбивающий начало исходящего потока на сегменты.
type fragmentConn struct {
	net.Conn
	cfg *TLSFragmentConfig

	pending     []byte
	planIndex   int
	passthrough bool
}

func (c *fragmentConn) Write(b []byte) (int, error) {
	if c.passthrough || !c.cfg.Enabled() {
		return c.Conn.Write(b)
	}

	c.pending = append(c.pending, b...)

	for c.planIndex < len(c.cfg.Sizes) {
		need := c.cfg.Sizes[c.planIndex]
		if need < 1 {
			need = 1
		}
		if len(c.pending) < need {
			break
		}
		if err := writeAll(c.Conn, c.pending[:need]); err != nil {
			return len(b), err
		}
		c.pending = c.pending[need:]
		c.planIndex++
		if c.cfg.Delay > 0 && c.planIndex < len(c.cfg.Sizes) {
			time.Sleep(c.cfg.Delay)
		}
	}

	if c.planIndex >= len(c.cfg.Sizes) {
		if len(c.pending) > 0 {
			if err := writeAll(c.Conn, c.pending); err != nil {
				return len(b), err
			}
			c.pending = nil
		}
		c.passthrough = true
	}

	return len(b), nil
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
