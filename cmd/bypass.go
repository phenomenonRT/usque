package cmd

import (
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

// defaultBypassConnectTimeout — сколько ждать одну комбинацию при переборе.
// Небольшое значение нужно, чтобы быстро пропускать молча заблокированные
// адреса (ТСПУ часто просто дропает пакеты, и попытка висит до таймаута).
const defaultBypassConnectTimeout = 5 * time.Second

// maxBypassCandidates ограничивает размер списка перебора, чтобы поиск рабочей
// комбинации не длился бесконечно.
const maxBypassCandidates = 64

// tunnelPlan — итог разбора флагов: либо одно подключение, либо набор
// кандидатов для перебора (режим --bypass).
type tunnelPlan struct {
	TLSConfig         *tls.Config
	Endpoint          net.Addr
	UseHTTP2          bool
	InitialPacketSize uint16
	Candidates        []api.TunnelCandidate
	Fragment          *api.TLSFragmentConfig
	ConnectTimeout    time.Duration
}

// addBypassFlags добавляет общие флаги обхода ТСПУ ко всем туннельным командам.
func addBypassFlags(c *cobra.Command) {
	c.Flags().Bool("bypass", false,
		"Обход блокировок ТСПУ (DPI): перебирать адреса, порты и SNI Cloudflare, дробить TLS ClientHello. Ничего в сервере не меняет.")
	c.Flags().StringArray("bypass-endpoint", nil,
		"Свои адреса сервера Cloudflare для перебора (можно несколько раз). Работает вместе с --bypass.")
	c.Flags().StringArray("bypass-sni", nil,
		"Свои SNI для перебора в режиме --bypass (можно несколько раз). Полностью заменяет встроенный список имён — пригодится, когда провайдер блокирует домены Cloudflare по SNI. Подходит любое незаблокированное имя.")
	c.Flags().Bool("tls-fragment", true,
		"В режиме --bypass дробить TLS ClientHello на несколько TCP-сегментов (для HTTP/2).")
	c.Flags().IntSlice("tls-fragment-sizes", []int{1},
		"Размеры первых сегментов TLS ClientHello в режиме --bypass (по умолчанию 1 байт, затем остальное).")
	c.Flags().Duration("connect-timeout", 0,
		"Таймаут одной попытки при переборе (--bypass). 0 — по умолчанию 5s.")
}

// buildTunnelPlan разбирает общие флаги команды и строит либо одиночное
// подключение, либо список кандидатов для обхода ТСПУ.
func buildTunnelPlan(cmd *cobra.Command, privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, useHTTP2, useIPv6 bool, connectPort int) (tunnelPlan, error) {
	sni, err := cmd.Flags().GetString("sni-address")
	if err != nil {
		return tunnelPlan{}, err
	}
	sniChanged := cmd.Flags().Changed("sni-address")

	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return tunnelPlan{}, err
	}

	initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
	if err != nil {
		return tunnelPlan{}, err
	}
	initialPacketSizeSet := cmd.Flags().Changed("initial-packet-size")

	bypass, err := cmd.Flags().GetBool("bypass")
	if err != nil {
		return tunnelPlan{}, err
	}

	plan := tunnelPlan{UseHTTP2: useHTTP2, InitialPacketSize: initialPacketSize}

	if !bypass {
		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
		if err != nil {
			return plan, err
		}
		endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
		if err != nil {
			return plan, err
		}
		plan.TLSConfig = tlsConfig
		plan.Endpoint = endpoint
		return plan, nil
	}

	// В режиме обхода по умолчанию ставим безопасный размер первого пакета и
	// отключаем PMTU-зондирование, если пользователь не задал своё значение.
	if !initialPacketSizeSet && plan.InitialPacketSize == 0 {
		plan.InitialPacketSize = internal.BypassInitialPacketSize
	}

	connectTimeout, err := cmd.Flags().GetDuration("connect-timeout")
	if err != nil {
		return plan, err
	}
	if connectTimeout <= 0 {
		connectTimeout = defaultBypassConnectTimeout
	}

	fragment := &api.TLSFragmentConfig{}
	if frag, err := cmd.Flags().GetBool("tls-fragment"); err != nil {
		return plan, err
	} else if frag {
		sizes, err := cmd.Flags().GetIntSlice("tls-fragment-sizes")
		if err != nil {
			return plan, err
		}
		fragment.Sizes = sizes
	}

	extraEndpoints, err := cmd.Flags().GetStringArray("bypass-endpoint")
	if err != nil {
		return plan, err
	}

	extraSNIs, err := cmd.Flags().GetStringArray("bypass-sni")
	if err != nil {
		return plan, err
	}

	snis := bypassSNIs(sni, sniChanged, extraSNIs, internal.BypassSNIs)
	tlsBySNI := make(map[string]*tls.Config, len(snis))
	for _, s := range snis {
		cfg, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, s, insecure)
		if err != nil {
			return plan, err
		}
		tlsBySNI[s] = cfg
	}

	pool := internal.BypassEndpointsV4
	if useIPv6 {
		pool = internal.BypassEndpointsV6
	}

	quicIPs := dedupeStrings(prefixEndpoint(configEndpoint(useIPv6), append(append([]string{}, pool...), extraEndpoints...)))
	h2IPs := dedupeStrings(prefixEndpoint(h2Endpoint(useIPv6), append(append([]string{}, pool...), extraEndpoints...)))
	if len(quicIPs) == 0 && len(h2IPs) == 0 {
		return plan, fmt.Errorf("нет адресов сервера для перебора")
	}

	ports := dedupeInts(prependInt(connectPort, internal.BypassQUICPorts))
	h2Ports := dedupeInts(prependInt(connectPort, []int{internal.BypassH2Port}))

	defaultSNI := snis[0]
	var candidates []api.TunnelCandidate
	seen := make(map[string]struct{})

	add := func(sni, ip string, isH2 bool, port int) {
		if len(candidates) >= maxBypassCandidates || ip == "" {
			return
		}
		tlsCfg := tlsBySNI[sni]
		if tlsCfg == nil {
			return
		}
		ipObj := net.ParseIP(ip)
		if ipObj == nil {
			return
		}
		key := fmt.Sprintf("%s|%s|%d|%t", sni, ip, port, isH2)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}

		var addr net.Addr
		transport := "quic"
		if isH2 {
			addr = &net.TCPAddr{IP: ipObj, Port: port}
			transport = "h2"
		} else {
			addr = &net.UDPAddr{IP: ipObj, Port: port}
		}
		candidates = append(candidates, api.TunnelCandidate{
			TLSConfig: tlsCfg,
			Endpoint:  addr,
			UseHTTP2:  isH2,
			Label:     fmt.Sprintf("%s %s:%d sni=%s", transport, ip, port, sni),
		})
	}

	// 1. Перебор портов и транспорта на основном адресе (ловит резаный UDP/порт).
	for _, p := range ports {
		add(defaultSNI, quicIPs[0], false, p)
	}
	for _, p := range h2Ports {
		add(defaultSNI, h2IPs[0], true, p)
	}
	// 2. Перебор SNI на основном адресе (ловит блокировку по имени).
	for _, s := range snis[1:] {
		add(s, quicIPs[0], false, 443)
		add(s, h2IPs[0], true, 443)
	}
	// 3. Перебор адресов сервера (ловит блокировку по IP/подсети).
	for _, ip := range quicIPs[1:] {
		add(defaultSNI, ip, false, 443)
	}
	for _, ip := range h2IPs[1:] {
		add(defaultSNI, ip, true, 443)
	}
	// 4. Перебор пар «адрес × SNI».
	for _, s := range snis[1:] {
		for _, ip := range quicIPs[1:] {
			add(s, ip, false, 443)
		}
	}

	if len(candidates) == 0 {
		return plan, fmt.Errorf("не удалось построить список подключений для обхода")
	}

	// Если пользователь просил HTTP/2, пробуем его первым: TSPU, режущий UDP,
	// иначе заставил бы ждать таймаут каждой QUIC-комбинации.
	if useHTTP2 {
		candidates = preferHTTP2(candidates)
	}

	plan.Candidates = candidates
	plan.Fragment = fragment
	plan.ConnectTimeout = connectTimeout
	return plan, nil
}

// preferHTTP2 переставляет HTTP/2-кандидаты в начало списка, сохраняя порядок.
func preferHTTP2(in []api.TunnelCandidate) []api.TunnelCandidate {
	out := make([]api.TunnelCandidate, 0, len(in))
	for _, c := range in {
		if c.UseHTTP2 {
			out = append(out, c)
		}
	}
	for _, c := range in {
		if !c.UseHTTP2 {
			out = append(out, c)
		}
	}
	return out
}

// bypassSNIs возвращает список SNI для перебора.
//
//   - extra (флаг --bypass-sni) полностью заменяет встроенный пул: если он
//     задан, перебираются ровно его значения (плюс sni, если -s указан явно).
//     Так можно уйти от блокировки доменов Cloudflare;
//   - иначе при явном -s используется только оно (перебор SNI отключается);
//   - иначе первым идёт имя из конфига команды (sni), затем пул pool.
func bypassSNIs(sni string, sniChanged bool, extra []string, pool []string) []string {
	if len(extra) > 0 {
		if sniChanged && sni != "" {
			return dedupeStrings(append([]string{sni}, extra...))
		}
		return dedupeStrings(extra)
	}
	if sniChanged && sni != "" {
		return []string{sni}
	}
	return dedupeStrings(append([]string{sni}, pool...))
}

// l4Plan — итог разбора флагов L4-прокси: либо одно HTTP/3-подключение, либо
// набор QUIC-кандидатов для обхода ТСПУ. HTTP/2 и дробление ClientHello здесь
// не применяются: L4-прокси работает только поверх QUIC.
type l4Plan struct {
	TLSConfig         *tls.Config
	Endpoint          *net.UDPAddr
	InitialPacketSize uint16
	Candidates        []api.TunnelCandidate
	CandidateTimeout  time.Duration
}

// buildL4Plan строит план подключения для команд l4-socks и l4-http-proxy.
// В режиме --bypass перебираются адреса/порты/SNI Cloudflare, но только по
// UDP (QUIC), потому что L4-прокси не умеет HTTP/2.
func buildL4Plan(cmd *cobra.Command, privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, useIPv6 bool, connectPort int, defaultSNI string) (l4Plan, error) {
	var plan l4Plan

	sni, err := cmd.Flags().GetString("sni-address")
	if err != nil {
		return plan, err
	}
	if sni == "" {
		sni = defaultSNI
	}
	sniChanged := cmd.Flags().Changed("sni-address")

	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return plan, err
	}

	if plan.InitialPacketSize, err = cmd.Flags().GetUint16("initial-packet-size"); err != nil {
		return plan, err
	}
	initialPacketSizeSet := cmd.Flags().Changed("initial-packet-size")

	bypass, err := cmd.Flags().GetBool("bypass")
	if err != nil {
		return plan, err
	}

	if !bypass {
		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
		if err != nil {
			return plan, err
		}
		endpointAddr, err := config.SelectEndpointFromConfig(false, useIPv6, connectPort)
		if err != nil {
			return plan, err
		}
		endpoint, ok := endpointAddr.(*net.UDPAddr)
		if !ok {
			return plan, fmt.Errorf("l4 proxy requires an HTTP/3 UDP endpoint")
		}
		plan.TLSConfig = tlsConfig
		plan.Endpoint = endpoint
		return plan, nil
	}

	// В режиме обхода по умолчанию ставим безопасный размер первого QUIC-пакета
	// и отключаем PMTU-зондирование, если пользователь не задал своё значение.
	if !initialPacketSizeSet && plan.InitialPacketSize == 0 {
		plan.InitialPacketSize = internal.BypassInitialPacketSize
	}

	connectTimeout, err := cmd.Flags().GetDuration("connect-timeout")
	if err != nil {
		return plan, err
	}
	if connectTimeout <= 0 {
		connectTimeout = defaultBypassConnectTimeout
	}

	extraEndpoints, err := cmd.Flags().GetStringArray("bypass-endpoint")
	if err != nil {
		return plan, err
	}

	extraSNIs, err := cmd.Flags().GetStringArray("bypass-sni")
	if err != nil {
		return plan, err
	}

	snis := bypassSNIs(sni, sniChanged, extraSNIs, internal.BypassSNIs)
	tlsBySNI := make(map[string]*tls.Config, len(snis))
	for _, s := range snis {
		cfg, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, s, insecure)
		if err != nil {
			return plan, err
		}
		tlsBySNI[s] = cfg
	}

	pool := internal.BypassEndpointsV4
	if useIPv6 {
		pool = internal.BypassEndpointsV6
	}
	ips := dedupeStrings(prefixEndpoint(configEndpoint(useIPv6), append(append([]string{}, pool...), extraEndpoints...)))
	if len(ips) == 0 {
		return plan, fmt.Errorf("нет адресов сервера для перебора")
	}

	ports := dedupeInts(prependInt(connectPort, internal.BypassQUICPorts))

	primarySNI := snis[0]
	var candidates []api.TunnelCandidate
	seen := make(map[string]struct{})

	add := func(sni, ip string, port int) {
		if len(candidates) >= maxBypassCandidates || ip == "" {
			return
		}
		tlsCfg := tlsBySNI[sni]
		if tlsCfg == nil {
			return
		}
		ipObj := net.ParseIP(ip)
		if ipObj == nil {
			return
		}
		key := fmt.Sprintf("%s|%s|%d", sni, ip, port)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}

		candidates = append(candidates, api.TunnelCandidate{
			TLSConfig: tlsCfg,
			Endpoint:  &net.UDPAddr{IP: ipObj, Port: port},
			Label:     fmt.Sprintf("quic %s:%d sni=%s", ip, port, sni),
		})
	}

	// 1. Перебор портов на основном адресе (ловит резаный UDP/порт).
	for _, p := range ports {
		add(primarySNI, ips[0], p)
	}
	// 2. Перебор SNI на основном адресе (ловит блокировку по имени).
	for _, s := range snis[1:] {
		add(s, ips[0], 443)
	}
	// 3. Перебор адресов сервера (ловит блокировку по IP/подсети).
	for _, ip := range ips[1:] {
		add(primarySNI, ip, 443)
	}
	// 4. Перебор пар «адрес × SNI».
	for _, s := range snis[1:] {
		for _, ip := range ips[1:] {
			add(s, ip, 443)
		}
	}

	if len(candidates) == 0 {
		return plan, fmt.Errorf("не удалось построить список подключений для обхода")
	}

	plan.Candidates = candidates
	plan.CandidateTimeout = connectTimeout
	return plan, nil
}

// configEndpoint возвращает адрес сервера QUIC из config.json.
func configEndpoint(useIPv6 bool) string {
	if useIPv6 {
		return config.AppConfig.EndpointV6
	}
	return config.AppConfig.EndpointV4
}

// h2Endpoint возвращает адрес сервера HTTP/2.
func h2Endpoint(useIPv6 bool) string {
	if useIPv6 {
		return config.AppConfig.EndpointH2V6
	}
	if config.AppConfig.EndpointH2V4 != "" {
		return config.AppConfig.EndpointH2V4
	}
	return config.DefaultEndpointH2V4
}

// prefixEndpoint ставит базовый адрес первым в списке, если он задан.
func prefixEndpoint(base string, rest []string) []string {
	out := make([]string, 0, len(rest)+1)
	if base != "" {
		out = append(out, base)
	}
	out = append(out, rest...)
	return out
}

// prependInt ставит значение первым, если оно задано.
func prependInt(first int, rest []int) []int {
	if first <= 0 {
		return append([]int{}, rest...)
	}
	return append([]int{first}, rest...)
}

// dedupeStrings убирает пустые значения и повторы, сохраняя порядок.
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// dedupeInts убирает неположительные значения и повторы, сохраняя порядок.
func dedupeInts(in []int) []int {
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, n := range in {
		if n <= 0 {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
