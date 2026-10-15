package cmd

import (
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
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

// bypassStateExt — суффикс файла с запомненной удачной комбинацией. По умолчанию
// файл лежит рядом с config.json (config.json.bypass) и переживает перезапуск.
const bypassStateExt = ".bypass"

// ipv6ProbeTimeout — сколько ждать ответа при проверке доступности IPv6. Это
// только проверка маршрута перед сборкой списка комбинаций, поэтому коротко.
const ipv6ProbeTimeout = 800 * time.Millisecond

// ipv6ProbeAddr — адрес для проверки IPv6 (DNS Google). Именно не-Cloudflare:
// адреса Cloudflare может резать тот же DPI, и проверка ложно показала бы, что
// IPv6 нет, хотя он есть.
const ipv6ProbeAddr = "[2001:4860:4860::8888]:443"

// tunnelPlan — итог разбора флагов: либо одно подключение, либо набор
// кандидатов для перебора (режим --bypass).
type tunnelPlan struct {
	TLSConfig         *tls.Config
	Endpoint          net.Addr
	UseHTTP2          bool
	InitialPacketSize uint16
	PacketSizeJitter  uint16
	Candidates        []api.TunnelCandidate
	Fragment          *api.TLSFragmentConfig
	ConnectTimeout    time.Duration
	Parallel          int
	// StatePath — файл с запомненной удачной комбинацией (пусто — не запоминать).
	StatePath string
}

// OnWinner возвращает обработчик успешного подключения: он запоминает
// комбинацию, чтобы следующее подключение начиналось с неё. nil — запоминание
// выключено.
func (p tunnelPlan) OnWinner() func(string) {
	if p.StatePath == "" {
		return nil
	}
	last := readBypassState(p.StatePath)
	return func(label string) {
		if label == "" || label == last {
			return
		}
		last = label
		if err := writeBypassState(p.StatePath, label); err != nil {
			log.Printf("Failed to remember bypass combination %q: %v", label, err)
			return
		}
		log.Printf("Запомнена рабочая комбинация обхода: %s", label)
	}
}

// addBypassFlags добавляет общие флаги обхода ТСПУ ко всем туннельным командам.
func addBypassFlags(c *cobra.Command) {
	c.Flags().Bool("bypass", false,
		"Обход блокировок ТСПУ (DPI): перебирать адреса, порты и SNI Cloudflare, дробить TLS ClientHello. Ничего в сервере не меняет.")
	c.Flags().StringArray("bypass-endpoint", nil,
		"Свои адреса сервера Cloudflare для перебора (можно несколько раз). Работает вместе с --bypass.")
	c.Flags().StringArray("bypass-sni", nil,
		"Свои SNI для перебора в режиме --bypass (можно несколько раз). Полностью заменяет встроенный список имён — пригодится, когда провайдер блокирует домены Cloudflare по SNI. Подходит любое незаблокированное имя.")
	c.Flags().String("tls-curve", "auto",
		"Профиль кривых TLS в режиме --bypass: auto (дефолты Go, ClientHello ~1.7 КБ с пост-квантовой долей), p256 (ClientHello ~300 Б, сервер не просит повторное рукопожатие), x25519. Противоположный профиль всё равно проверяется отдельными комбинациями.")
	c.Flags().Bool("bypass-no-sni", true,
		"В режиме --bypass пробовать также рукопожатие вообще без SNI: DPI нечего сопоставлять с именем. Сертификат проверяется по ключу, имя серверу не нужно.")
	c.Flags().IntSlice("bypass-source-port", nil,
		"Порты источника UDP для отдельных комбинаций в режиме --bypass (эксперимент: часть DPI фильтрует по порту источника). Требует прав на порты <1024.")
	c.Flags().Bool("bypass-ipv6-fallback", true,
		"В режиме --bypass добавлять IPv6-комбинации, если IPv6 в сети работает, а флаг -6 не задан (провайдеры часто фильтруют IPv4 жёстче).")
	c.Flags().String("bypass-state", "",
		"Файл, в котором запоминается удачная комбинация обхода: следующее подключение начнётся с неё (по умолчанию рядом с config.json). \"-\" отключает запоминание.")
	c.Flags().Bool("tls-fragment", true,
		"В режиме --bypass дробить TLS ClientHello так, чтобы имя сервера (SNI) разрывалось между TCP-сегментами (для HTTP/2).")
	c.Flags().IntSlice("tls-fragment-sizes", nil,
		"Явные размеры первых сегментов TLS ClientHello в режиме --bypass (по умолчанию два разрыва внутри SNI).")
	c.Flags().Int("tls-fragment-jitter", internal.BypassFragmentJitter,
		"Случайное смещение точек разрыва TLS ClientHello в байтах (±) в режиме --bypass: постоянные точки разрыва сами являются признаком.")
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
	if cfg.Jitter, err = cmd.Flags().GetInt("tls-fragment-jitter"); err != nil {
		return nil, err
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	}
	return cfg, nil
}

// bypassArgs — входные данные подготовки перебора, общие для туннеля и L4-прокси.
type bypassArgs struct {
	privKey     *ecdsa.PrivateKey
	peerPubKey  *ecdsa.PublicKey
	cert        [][]byte
	sni         string
	sniChanged  bool
	insecure    bool
	useIPv6     bool
	connectPort int
}

// bypassSetup — готовые к сборке списки: имена, TLS-конфигурации, адреса, порты
// и общие параметры перебора.
type bypassSetup struct {
	snis        []string
	tlsBySNI    map[string]*tls.Config
	tlsAlt      *tls.Config
	altCurve    string
	noSNI       *tls.Config
	quicIPs     []string
	h2IPs       []string
	quicIPsV6   []string
	h2IPsV6     []string
	ports       []int
	h2Ports     []int
	sourcePorts []int
	fragment    *api.TLSFragmentConfig
	timeout     time.Duration
	parallel    int
	statePath   string
	remembered  string
}

// prepareBypass разбирает флаги обхода и готовит всё, из чего собирается список
// комбинаций. Используется и туннелем, и L4-прокси.
func prepareBypass(cmd *cobra.Command, a bypassArgs) (bypassSetup, error) {
	var s bypassSetup

	curveName, err := cmd.Flags().GetString("tls-curve")
	if err != nil {
		return s, err
	}
	curves, err := internal.TLSCurvesForName(curveName)
	if err != nil {
		return s, err
	}
	altCurve := internal.AlternateCurveName(curveName)
	altCurves, err := internal.TLSCurvesForName(altCurve)
	if err != nil {
		return s, err
	}

	extraEndpoints, err := cmd.Flags().GetStringArray("bypass-endpoint")
	if err != nil {
		return s, err
	}

	extraSNIs, err := cmd.Flags().GetStringArray("bypass-sni")
	if err != nil {
		return s, err
	}

	s.snis = bypassSNIs(a.sni, a.sniChanged, extraSNIs, internal.BypassSNIs)
	primarySNI := s.snis[0]

	s.tlsBySNI = make(map[string]*tls.Config, len(s.snis))
	for _, name := range s.snis {
		cfg, err := api.PrepareTlsConfig(a.privKey, a.peerPubKey, a.cert, name, a.insecure)
		if err != nil {
			return s, err
		}
		cfg.CurvePreferences = curves
		s.tlsBySNI[name] = cfg
	}

	// Противоположный профиль кривых проверяется отдельными комбинациями: так
	// перебор не зависит от того, какую кривую поддерживает сервер.
	if altCurve != "" {
		cfg, err := api.PrepareTlsConfig(a.privKey, a.peerPubKey, a.cert, primarySNI, a.insecure)
		if err != nil {
			return s, err
		}
		cfg.CurvePreferences = altCurves
		s.tlsAlt = cfg
		s.altCurve = altCurve
	}

	noSNI, err := cmd.Flags().GetBool("bypass-no-sni")
	if err != nil {
		return s, err
	}
	if noSNI {
		// Пустое имя сервера — Go не отправляет расширение SNI вообще.
		cfg, err := api.PrepareTlsConfig(a.privKey, a.peerPubKey, a.cert, "", a.insecure)
		if err != nil {
			return s, err
		}
		cfg.CurvePreferences = curves
		s.noSNI = cfg
	}

	pool := internal.BypassEndpointsV4
	if a.useIPv6 {
		pool = internal.BypassEndpointsV6
	}
	s.quicIPs = dedupeStrings(prefixEndpoint(configEndpoint(a.useIPv6), append(append([]string{}, pool...), extraEndpoints...)))
	s.h2IPs = dedupeStrings(prefixEndpoint(h2Endpoint(a.useIPv6), append(append([]string{}, pool...), extraEndpoints...)))
	if len(s.quicIPs) == 0 && len(s.h2IPs) == 0 {
		return s, fmt.Errorf("нет адресов сервера для перебора")
	}

	// IPv6-запас: если IPv6 в сети работает и его не выбрали явно, часть
	// перебора отдаётся под него.
	fallback, err := cmd.Flags().GetBool("bypass-ipv6-fallback")
	if err != nil {
		return s, err
	}
	if !a.useIPv6 && fallback && probeIPv6() {
		s.quicIPsV6 = dedupeStrings(prefixEndpoint(configEndpoint(true), append(append([]string{}, internal.BypassEndpointsV6...), extraEndpoints...)))
		s.h2IPsV6 = dedupeStrings(prefixEndpoint(h2Endpoint(true), append(append([]string{}, internal.BypassEndpointsV6...), extraEndpoints...)))
	}

	s.ports = dedupeInts(prependInt(a.connectPort, internal.BypassQUICPorts))
	s.h2Ports = dedupeInts(prependInt(a.connectPort, []int{internal.BypassH2Port}))

	sourcePorts, err := cmd.Flags().GetIntSlice("bypass-source-port")
	if err != nil {
		return s, err
	}
	s.sourcePorts = dedupePorts(sourcePorts)

	if s.timeout, err = cmd.Flags().GetDuration("connect-timeout"); err != nil {
		return s, err
	}
	if s.timeout <= 0 {
		s.timeout = defaultBypassConnectTimeout
	}

	if s.parallel, err = bypassParallel(cmd); err != nil {
		return s, err
	}

	if s.fragment, err = buildTLSFragment(cmd); err != nil {
		return s, err
	}

	s.statePath = bypassStatePath(cmd)
	s.remembered = readBypassState(s.statePath)
	return s, nil
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
	plan.PacketSizeJitter = internal.BypassPacketSizeJitter

	setup, err := prepareBypass(cmd, bypassArgs{
		privKey:     privKey,
		peerPubKey:  peerPubKey,
		cert:        cert,
		sni:         sni,
		sniChanged:  sniChanged,
		insecure:    insecure,
		useIPv6:     useIPv6,
		connectPort: connectPort,
	})
	if err != nil {
		return plan, err
	}

	in := candidateInput{
		SNIs:         setup.snis,
		TLSBySNI:     setup.tlsBySNI,
		TLSConfigAlt: setup.tlsAlt,
		AltCurve:     setup.altCurve,
		NoSNI:        setup.noSNI,
		QUICIPs:      setup.quicIPs,
		H2IPs:        setup.h2IPs,
		Ports:        setup.ports,
		H2Ports:      setup.h2Ports,
		SourcePorts:  setup.sourcePorts,
		UseHTTP2:     useHTTP2,
	}
	candidates := buildCandidates(in)

	if len(setup.quicIPsV6) > 0 || len(setup.h2IPsV6) > 0 {
		in.QUICIPs, in.H2IPs = setup.quicIPsV6, setup.h2IPsV6
		if extra := buildCandidates(in); len(extra) > 0 {
			log.Printf("IPv6 доступен: в перебор добавлено комбинаций с IPv6: %d", len(extra))
			candidates = appendWithinCap(candidates, extra)
		}
	}

	if len(candidates) == 0 {
		return plan, fmt.Errorf("не удалось построить список подключений для обхода")
	}

	if list, ok := preferRememberedCandidate(candidates, setup.remembered); ok {
		candidates = list
		log.Printf("Рабочая комбинация из прошлого запуска: %s", setup.remembered)
	} else if setup.remembered != "" {
		log.Printf("Запомненная комбинация %q больше не подходит: перебор с начала", setup.remembered)
	}

	plan.Candidates = candidates
	plan.Fragment = setup.fragment
	plan.ConnectTimeout = setup.timeout
	plan.Parallel = setup.parallel
	plan.StatePath = setup.statePath
	return plan, nil
}

// candidateInput — всё, что нужно, чтобы собрать список комбинаций для перебора.
type candidateInput struct {
	// SNIs — имена в порядке перебора; первое используется в переборах портов
	// и адресов.
	SNIs []string
	// TLSBySNI сопоставляет имя готовой конфигурации TLS.
	TLSBySNI map[string]*tls.Config
	// TLSConfigAlt — конфигурация с противоположным профилем кривых TLS для
	// первого имени; nil отключает такую проверку.
	TLSConfigAlt *tls.Config
	// AltCurve — как назвать альтернативный профиль в подписи комбинации.
	AltCurve string
	// NoSNI — конфигурация без имени сервера: рукопожатие совсем без SNI.
	NoSNI *tls.Config
	// QUICIPs и H2IPs — адреса сервера для QUIC и HTTP/2 соответственно.
	QUICIPs []string
	H2IPs   []string
	// Ports — порты UDP для перебора, H2Ports — порты TCP для основного адреса.
	Ports   []int
	H2Ports []int
	// SourcePorts — порты источника UDP для отдельных комбинаций.
	SourcePorts []int
	// UseHTTP2 — пользователь явно попросил HTTP/2, тогда он идёт первым.
	UseHTTP2 bool
}

// buildCandidates собирает список комбинаций «адрес + порт + транспорт + SNI».
//
// Порядок «в ширину»: за первые два десятка попыток пробуются все измерения
// (транспорт, порт, SNI, адрес, профиль TLS), а не исчерпывается одно.
// Заблокированная комбинация стоит полного таймаута, поэтому ширина важнее
// глубины: рабочая комбинация находится за десятки секунд, а не за минуты.
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

	// add добавляет одну комбинацию. tlsOverride заменяет конфигурацию TLS
	// (альтернативная кривая или рукопожатие без имени), note уходит в подпись,
	// localPort задаёт порт источника UDP.
	add := func(sni, ip string, isH2 bool, port int, tlsOverride *tls.Config, note string, localPort int) {
		if len(candidates) >= maxBypassCandidates || ip == "" || port <= 0 {
			return
		}
		tlsCfg := tlsOverride
		if tlsCfg == nil {
			tlsCfg = in.TLSBySNI[sni]
		}
		if tlsCfg == nil {
			return
		}
		ipObj := net.ParseIP(ip)
		if ipObj == nil {
			return
		}
		key := fmt.Sprintf("%s|%s|%d|%t|%s|%d", sni, ip, port, isH2, note, localPort)
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

		label := fmt.Sprintf("%s %s:%d", transport, ip, port)
		if sni != "" {
			label += " sni=" + sni
		}
		if note != "" {
			label += " " + note
		}

		candidates = append(candidates, api.TunnelCandidate{
			TLSConfig: tlsCfg,
			Endpoint:  addr,
			UseHTTP2:  isH2,
			Label:     label,
			LocalPort: localPort,
		})
	}

	// 1. Оба транспорта на основном адресе: сначала QUIC (быстрее), затем
	//    HTTP/2 с дроблением ClientHello.
	add(primarySNI, primaryQUIC, false, quicPort, nil, "", 0)
	for _, p := range in.H2Ports {
		add(primarySNI, primaryH2, true, p, nil, "", 0)
	}

	// 2. Рукопожатие без SNI: DPI нечего сопоставлять с именем. По одной
	//    попытке на транспорт — сервер такое принимает не всегда.
	if in.NoSNI != nil {
		add("", primaryQUIC, false, quicPort, in.NoSNI, "без SNI", 0)
		add("", primaryH2, true, h2Port, in.NoSNI, "без SNI", 0)
	}

	// 3. Противоположный профиль кривых TLS: ClientHello другого размера и
	//    другой формы. Если сервер просит повторное рукопожатие (HRR) или не
	//    принимает предложенную кривую, срабатывает именно эта попытка.
	if in.TLSConfigAlt != nil {
		add(primarySNI, primaryQUIC, false, quicPort, in.TLSConfigAlt, "curve="+in.AltCurve, 0)
		add(primarySNI, primaryH2, true, h2Port, in.TLSConfigAlt, "curve="+in.AltCurve, 0)
	}

	// 4. Свои порты источника UDP — против DPI, который фильтрует по ним.
	for _, sp := range in.SourcePorts {
		add(primarySNI, primaryQUIC, false, quicPort, nil, fmt.Sprintf("sport=%d", sp), sp)
	}

	// 5. Запасные UDP-порты Cloudflare (порт-хопинг) на основном адресе.
	for _, p := range in.Ports[1:] {
		add(primarySNI, primaryQUIC, false, p, nil, "", 0)
	}

	// 6. Прочие SNI на основном адресе. HTTP/2 идёт первым: там ClientHello
	//    дробится и имя сервера не видно DPI целиком.
	for _, s := range in.SNIs[1:] {
		add(s, primaryH2, true, h2Port, nil, "", 0)
		add(s, primaryQUIC, false, quicPort, nil, "", 0)
	}

	// 7. Прочие адреса сервера — оба транспорта по разу.
	for i := 1; i < len(in.QUICIPs) || i < len(in.H2IPs); i++ {
		if i < len(in.H2IPs) {
			add(primarySNI, in.H2IPs[i], true, h2Port, nil, "", 0)
		}
		if i < len(in.QUICIPs) {
			add(primarySNI, in.QUICIPs[i], false, quicPort, nil, "", 0)
		}
	}

	// 8. Оставшиеся пары «адрес × SNI».
	for _, s := range in.SNIs[1:] {
		for i := 1; i < len(in.QUICIPs) || i < len(in.H2IPs); i++ {
			if i < len(in.QUICIPs) {
				add(s, in.QUICIPs[i], false, quicPort, nil, "", 0)
			}
			if i < len(in.H2IPs) {
				add(s, in.H2IPs[i], true, h2Port, nil, "", 0)
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

// appendWithinCap присоединяет вторую часть перебора (IPv6), отдавая ей не
// больше четверти общего лимита: обычно IPv6-комбинации нужны не первыми, но
// если IPv4 блокируют целиком, без них перебора просто не хватит.
func appendWithinCap(base, extra []api.TunnelCandidate) []api.TunnelCandidate {
	if len(extra) == 0 {
		return base
	}
	limit := maxBypassCandidates - maxBypassCandidates/4
	if len(base) > limit {
		base = base[:limit]
	}
	out := make([]api.TunnelCandidate, 0, maxBypassCandidates)
	out = append(out, base...)
	out = append(out, extra...)
	if len(out) > maxBypassCandidates {
		out = out[:maxBypassCandidates]
	}
	return out
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

// probeIPv6 проверяет, ходит ли IPv6 наружу. Соединение нужно только чтобы
// убедиться, что маршрут есть: данные не передаются.
func probeIPv6() bool {
	conn, err := net.DialTimeout("tcp6", ipv6ProbeAddr, ipv6ProbeTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// bypassStatePath возвращает путь к файлу с запомненной комбинацией обхода.
// Пустая строка — запоминание выключено.
func bypassStatePath(cmd *cobra.Command) string {
	raw, err := cmd.Flags().GetString("bypass-state")
	if err != nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "-", "off", "none":
		return ""
	case "":
		cfgPath, err := cmd.Flags().GetString("config")
		if err != nil || cfgPath == "" {
			return ""
		}
		return cfgPath + bypassStateExt
	default:
		return raw
	}
}

// readBypassState читает запомненную комбинацию. Пусто — файла нет или он пуст.
func readBypassState(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// writeBypassState сохраняет комбинацию в файл (создаётся только для root).
func writeBypassState(path, label string) error {
	if path == "" || label == "" {
		return nil
	}
	return os.WriteFile(path, []byte(label+"\n"), 0o600)
}

// preferRememberedCandidate поднимает в начало списка комбинацию, которая
// сработала в прошлый раз: перебор в этом случае заканчивается первой попыткой.
// Второе значение — нашлась ли она: файл мог остаться от другой сети.
func preferRememberedCandidate(cands []api.TunnelCandidate, label string) ([]api.TunnelCandidate, bool) {
	if label == "" {
		return cands, false
	}
	for i, c := range cands {
		if c.Label != label {
			continue
		}
		if i == 0 {
			return cands, true
		}
		out := make([]api.TunnelCandidate, 0, len(cands))
		out = append(out, c)
		out = append(out, cands[:i]...)
		return append(out, cands[i+1:]...), true
	}
	return cands, false
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
	PacketSizeJitter  uint16
	Candidates        []api.TunnelCandidate
	CandidateTimeout  time.Duration
	Parallel          int
	StatePath         string
}

// OnWinner возвращает обработчик успешного подключения L4-прокси: он запоминает
// комбинацию, чтобы следующее подключение начиналось с неё.
func (p l4Plan) OnWinner() func(string) {
	return tunnelPlan{StatePath: p.StatePath}.OnWinner()
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
	plan.PacketSizeJitter = internal.BypassPacketSizeJitter

	setup, err := prepareBypass(cmd, bypassArgs{
		privKey:     privKey,
		peerPubKey:  peerPubKey,
		cert:        cert,
		sni:         sni,
		sniChanged:  sniChanged,
		insecure:    insecure,
		useIPv6:     useIPv6,
		connectPort: connectPort,
	})
	if err != nil {
		return plan, err
	}

	// H2IPs/H2Ports не задаются: L4-прокси работает только поверх QUIC, и
	// сборщик комбинаций сам пропустит HTTP/2.
	in := candidateInput{
		SNIs:         setup.snis,
		TLSBySNI:     setup.tlsBySNI,
		TLSConfigAlt: setup.tlsAlt,
		AltCurve:     setup.altCurve,
		NoSNI:        setup.noSNI,
		QUICIPs:      setup.quicIPs,
		Ports:        setup.ports,
		SourcePorts:  setup.sourcePorts,
	}
	candidates := buildCandidates(in)

	if len(setup.quicIPsV6) > 0 {
		in.QUICIPs = setup.quicIPsV6
		if extra := buildCandidates(in); len(extra) > 0 {
			log.Printf("IPv6 доступен: в перебор добавлено комбинаций с IPv6: %d", len(extra))
			candidates = appendWithinCap(candidates, extra)
		}
	}

	if len(candidates) == 0 {
		return plan, fmt.Errorf("не удалось построить список подключений для обхода")
	}

	if list, ok := preferRememberedCandidate(candidates, setup.remembered); ok {
		candidates = list
		log.Printf("Рабочая комбинация из прошлого запуска: %s", setup.remembered)
	} else if setup.remembered != "" {
		log.Printf("Запомненная комбинация %q больше не подходит: перебор с начала", setup.remembered)
	}

	plan.Candidates = candidates
	plan.CandidateTimeout = setup.timeout
	plan.Parallel = setup.parallel
	plan.StatePath = setup.statePath
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

// dedupePorts убирает повторы и значения вне диапазона портов.
func dedupePorts(in []int) []int {
	out := make([]int, 0, len(in))
	for _, n := range dedupeInts(in) {
		if n > 65535 {
			continue
		}
		out = append(out, n)
	}
	return out
}
