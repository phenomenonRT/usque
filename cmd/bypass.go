package cmd

import (
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
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
	Parallel          int
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
		"В режиме --bypass дробить TLS ClientHello так, чтобы имя сервера (SNI) разрывалось между TCP-сегментами (для HTTP/2).")
	c.Flags().IntSlice("tls-fragment-sizes", nil,
		"Явные размеры первых сегментов TLS ClientHello в режиме --bypass (по умолчанию разрыв в середине SNI).")
	c.Flags().Duration("tls-fragment-delay", 0,
		"Пауза между сегментами TLS ClientHello в режиме --bypass (0 — без паузы).")
	c.Flags().Duration("connect-timeout", 0,
		"Таймаут одной попытки при переборе (--bypass). 0 — по умолчанию 5s.")
	c.Flags().Int("bypass-parallel", 3,
		"Сколько комбинаций пробовать одновременно в режиме --bypass (1 — по очереди). Больше — быстрее поиск, но заметнее для DPI.")
}

// buildTLSFragment собирает настройки дробления TLS ClientHello из флагов.
// Возвращает nil, если дробление выключено.
func buildTLSFragment(cmd *cobra.Command) (*api.TLSFragmentConfig, error) {
	frag, err := cmd.Flags().GetBool("tls-fragment")
	if err != nil || !frag {
		return nil, err
	}

	cfg := &api.TLSFragmentConfig{Auto: true}
	if cmd.Flags().Changed("tls-fragment-sizes") {
		sizes, err := cmd.Flags().GetIntSlice("tls-fragment-sizes")
		if err != nil {
			return nil, err
		}
		if len(sizes) > 0 {
			cfg.Sizes = sizes
			cfg.Auto = false
		}
	}
	if cfg.Delay, err = cmd.Flags().GetDuration("tls-fragment-delay"); err != nil {
		return nil, err
	}
	return cfg, nil
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

	fragment, err := buildTLSFragment(cmd)
	if err != nil {
		return plan, err
	}

	parallel, err := bypassParallel(cmd)
	if err != nil {
		return plan, err
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

	candidates := buildCandidates(candidateInput{
		SNIs:     snis,
		TLSBySNI: tlsBySNI,
		QUICIPs:  quicIPs,
		H2IPs:    h2IPs,
		Ports:    ports,
		H2Ports:  h2Ports,
		UseHTTP2: useHTTP2,
	})
	if len(candidates) == 0 {
		return plan, fmt.Errorf("не удалось построить список подключений для обхода")
	}

	plan.Candidates = candidates
	plan.Fragment = fragment
	plan.ConnectTimeout = connectTimeout
	plan.Parallel = parallel
	return plan, nil
}

// candidateInput — всё, что нужно, чтобы собрать список комбинаций для перебора.
type candidateInput struct {
	// SNIs — имена в порядке перебора; первое используется в переборах портов
	// и адресов.
	SNIs []string
	// TLSBySNI сопоставляет имя готовой конфигурации TLS.
	TLSBySNI map[string]*tls.Config
	// QUICIPs и H2IPs — адреса сервера для QUIC и HTTP/2 соответственно.
	QUICIPs []string
	H2IPs   []string
	// Ports — порты UDP для перебора, H2Ports — порты TCP для основного адреса.
	Ports   []int
	H2Ports []int
	// UseHTTP2 — пользователь явно попросил HTTP/2, тогда он идёт первым.
	UseHTTP2 bool
}

// buildCandidates собирает список комбинаций «адрес + порт + транспорт + SNI».
//
// Порядок «в ширину»: за первые два десятка попыток пробуются все измерения
// (транспорт, порт, SNI, адрес), а не исчерпывается одно. Заблокированная
// комбинация стоит полного таймаута, поэтому ширина важнее глубины: рабочая
// комбинация находится за десятки секунд, а не за минуты.
func buildCandidates(in candidateInput) []api.TunnelCandidate {
	if len(in.SNIs) == 0 {
		return nil
	}

	primarySNI := in.SNIs[0]
	quicPort := internal.BypassQUICPorts[0]
	if len(in.Ports) > 0 {
		quicPort = in.Ports[0]
	}
	h2Port := internal.BypassH2Port
	primaryQUIC := firstOrEmpty(in.QUICIPs)
	primaryH2 := firstOrEmpty(in.H2IPs)

	var candidates []api.TunnelCandidate
	seen := make(map[string]struct{})

	add := func(sni, ip string, isH2 bool, port int) {
		if len(candidates) >= maxBypassCandidates || ip == "" {
			return
		}
		tlsCfg := in.TLSBySNI[sni]
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

	// 1. Оба транспорта на основном адресе: сначала QUIC (быстрее), затем
	//    HTTP/2 с дроблением ClientHello.
	add(primarySNI, primaryQUIC, false, quicPort)
	for _, p := range in.H2Ports {
		add(primarySNI, primaryH2, true, p)
	}

	// 2. Запасные UDP-порты Cloudflare (порт-хопинг) на основном адресе.
	for _, p := range in.Ports[1:] {
		add(primarySNI, primaryQUIC, false, p)
	}

	// 3. Прочие SNI на основном адресе. HTTP/2 идёт первым: там ClientHello
	//    дробится и имя сервера не видно DPI целиком.
	for _, s := range in.SNIs[1:] {
		add(s, primaryH2, true, h2Port)
		add(s, primaryQUIC, false, quicPort)
	}

	// 4. Прочие адреса сервера — оба транспорта по разу.
	for i := 1; i < len(in.QUICIPs) || i < len(in.H2IPs); i++ {
		if i < len(in.H2IPs) {
			add(primarySNI, in.H2IPs[i], true, h2Port)
		}
		if i < len(in.QUICIPs) {
			add(primarySNI, in.QUICIPs[i], false, quicPort)
		}
	}

	// 5. Оставшиеся пары «адрес × SNI».
	for _, s := range in.SNIs[1:] {
		for i := 1; i < len(in.QUICIPs) || i < len(in.H2IPs); i++ {
			if i < len(in.QUICIPs) {
				add(s, in.QUICIPs[i], false, quicPort)
			}
			if i < len(in.H2IPs) {
				add(s, in.H2IPs[i], true, h2Port)
			}
		}
	}

	// Если пользователь просил HTTP/2, пробуем его первым: TSPU, режущий UDP,
	// иначе заставил бы ждать таймаут каждой QUIC-комбинации.
	if in.UseHTTP2 {
		candidates = preferHTTP2(candidates)
	}
	return candidates
}

// bypassParallel читает --bypass-parallel и держит значение в разумных рамках.
func bypassParallel(cmd *cobra.Command) (int, error) {
	n, err := cmd.Flags().GetInt("bypass-parallel")
	if err != nil {
		return 0, err
	}
	if n < 1 {
		n = 1
	}
	if n > 16 {
		n = 16
	}
	return n, nil
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
//   - иначе первым идёт имя из конфига команды (sni), затем пул pool. Имена вне
//     Cloudflare поднимаются в начало: сервер принимает любое имя, а ТСПУ режет
//     домены Cloudflare по SNI.
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
	return orderSNIsForSweep(dedupeStrings(append([]string{sni}, pool...)))
}

// orderSNIsForSweep поднимает в начало имена вне Cloudflare, сохраняя
// относительный порядок внутри групп. Сервер MASQUE принимает любое имя
// (привязка идёт к публичному ключу), поэтому начинать с доменов Cloudflare,
// которые ТСПУ режет по SNI, смысла нет.
func orderSNIsForSweep(snis []string) []string {
	neutral := make([]string, 0, len(snis))
	cloudflare := make([]string, 0, len(snis))
	for _, s := range snis {
		if isCloudflareName(s) {
			cloudflare = append(cloudflare, s)
			continue
		}
		neutral = append(neutral, s)
	}
	return append(neutral, cloudflare...)
}

// isCloudflareName — грубая проверка, что имя принадлежит Cloudflare: ТСПУ
// блокирует домены Cloudflare целиком, поэтому такие имена пробуем последними.
func isCloudflareName(s string) bool {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	switch s {
	case "one.one.one.one", "1.1.1.1":
		return true
	}
	for _, suffix := range []string{"cloudflare.com", "cloudflareclient.com", "cloudflare-dns.com"} {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
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
	Parallel          int
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

	parallel, err := bypassParallel(cmd)
	if err != nil {
		return plan, err
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
	primaryIP := firstOrEmpty(ips)
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

	// Порядок «в ширину»: сначала пробуются все измерения (порт, SNI, адрес), а
	// не исчерпывается одно. См. buildTunnelPlan.
	for _, p := range ports {
		add(primarySNI, primaryIP, p)
	}
	for _, s := range snis[1:] {
		add(s, primaryIP, 443)
	}
	for i := 1; i < len(ips); i++ {
		add(primarySNI, ips[i], 443)
	}
	for _, s := range snis[1:] {
		for i := 1; i < len(ips); i++ {
			add(s, ips[i], 443)
		}
	}

	if len(candidates) == 0 {
		return plan, fmt.Errorf("не удалось построить список подключений для обхода")
	}

	plan.Candidates = candidates
	plan.CandidateTimeout = connectTimeout
	plan.Parallel = parallel
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

// firstOrEmpty возвращает первый элемент списка или пустую строку, если он пуст.
// Список адресов может состоять только из записей, которые не разбираются как
// IP, поэтому обращаться к элементам напрямую нельзя.
func firstOrEmpty(in []string) string {
	if len(in) == 0 {
		return ""
	}
	return in[0]
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
