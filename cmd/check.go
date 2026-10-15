package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

// checkCmd проверяет работоспособность подключения, не трогая систему: TUN не
// создаётся, маршруты и адреса не меняются. Полезно как кнопка «Проверить» в
// LuCI и для диагностики вне роутера.
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Проверить подключение к MASQUE и подобрать рабочую комбинацию",
	Long: "Подключается к Cloudflare MASQUE, перебирая адреса сервера, порты, SNI и транспорт " +
		"(в том же порядке, что и режим --bypass), и сообщает первую рабочую комбинацию. " +
		"Ничего в системе не меняет: TUN-устройство не создаётся, адреса и маршруты не трогаются.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !config.ConfigLoaded {
			return fmt.Errorf("config not loaded: please register first")
		}

		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to get private key: %w", err)
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}
		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to generate cert: %w", err)
		}

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			return err
		}
		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			return err
		}
		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			return err
		}
		useHTTP2, err := cmd.Flags().GetBool("http2")
		if err != nil {
			return err
		}
		useIPv6, err := cmd.Flags().GetBool("ipv6")
		if err != nil {
			return err
		}
		testAll, err := cmd.Flags().GetBool("all")
		if err != nil {
			return err
		}

		if insecure {
			config.WarnInsecure()
		}

		plan, err := buildTunnelPlan(cmd, privKey, peerPubKey, cert, useHTTP2, useIPv6, connectPort)
		if err != nil {
			return err
		}

		candidates := plan.Candidates
		if len(candidates) == 0 {
			label := "config endpoint"
			if plan.Endpoint != nil {
				label = plan.Endpoint.String()
			}
			candidates = []api.TunnelCandidate{{
				TLSConfig: plan.TLSConfig,
				Endpoint:  plan.Endpoint,
				UseHTTP2:  useHTTP2,
				Label:     label,
			}}
		}

		timeout := plan.ConnectTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}

		parallel := plan.Parallel
		if parallel < 1 {
			parallel = 1
		}
		if parallel > len(candidates) {
			parallel = len(candidates)
		}

		cmd.Printf("Проверка подключения: %d комбинаций, таймаут одной попытки %s, одновременно %d\n",
			len(candidates), timeout, parallel)
		if len(plan.Candidates) == 0 {
			cmd.Println("(обход не включён — проверяется только текущий способ)")
		}

		type checkResult struct {
			idx    int
			reason string
		}

		runCtx, cancelAll := context.WithCancel(ctx)
		defer cancelAll()

		results := make(chan checkResult, parallel)
		launched, inFlight := 0, 0
		launch := func() {
			idx := launched
			cand := candidates[idx]
			launched++
			inFlight++
			go func() {
				results <- checkResult{
					idx:    idx,
					reason: checkCandidate(runCtx, cand, keepalivePeriod, plan.InitialPacketSize, plan.Fragment, timeout),
				}
			}()
		}

		for inFlight < parallel && launched < len(candidates) {
			launch()
		}

		okCount := 0
		firstOK := ""
		outcomes := make([]*checkOutcome, len(candidates))
		for inFlight > 0 {
			var res checkResult
			select {
			case <-ctx.Done():
				return ctx.Err()
			case res = <-results:
			}
			inFlight--

			cand := candidates[res.idx]
			outcomes[res.idx] = outcomeOf(cand, res.reason == "")
			if res.reason == "" {
				okCount++
				if firstOK == "" {
					firstOK = cand.Label
				}
				cmd.Printf("[%d/%d] OK   %s\n", res.idx+1, len(candidates), cand.Label)
				if !testAll {
					cancelAll() // останавливаем ещё идущие попытки
					break
				}
			} else {
				cmd.Printf("[%d/%d] нет  %s — %s\n", res.idx+1, len(candidates), cand.Label, res.reason)
			}

			if launched < len(candidates) && ctx.Err() == nil {
				launch()
			}
		}

		// Итог в терминах того, что именно мешает: это и есть ответ на вопрос
		// «работает ли обход в моей сети и почему нет».
		verdict := checkVerdict(collectOutcomes(outcomes))
		for _, line := range verdict {
			cmd.Printf("Вывод: %s\n", line)
		}

		if okCount == 0 {
			cmd.Println("Результат: ни одна комбинация не сработала.")
			return fmt.Errorf("не удалось подключиться")
		}
		cmd.Printf("Результат: работает %d из %d. Рабочая комбинация: %s\n", okCount, len(candidates), firstOK)
		return nil
	},
}

// checkOutcome — то, что нужно знать о попытке, чтобы объяснить её результат.
type checkOutcome struct {
	useHTTP2 bool
	sni      string
	port     int
	ok       bool
}

// outcomeOf снимает параметры попытки с кандидата.
func outcomeOf(cand api.TunnelCandidate, ok bool) *checkOutcome {
	out := &checkOutcome{useHTTP2: cand.UseHTTP2, ok: ok}
	if cand.TLSConfig != nil {
		out.sni = cand.TLSConfig.ServerName
	}
	switch addr := cand.Endpoint.(type) {
	case *net.UDPAddr:
		out.port = addr.Port
	case *net.TCPAddr:
		out.port = addr.Port
	}
	return out
}

// collectOutcomes оставляет только выполненные попытки, сохраняя их порядок в
// списке кандидатов.
func collectOutcomes(slots []*checkOutcome) []checkOutcome {
	out := make([]checkOutcome, 0, len(slots))
	for _, slot := range slots {
		if slot != nil {
			out = append(out, *slot)
		}
	}
	return out
}

// checkVerdict переводит результаты попыток на человеческий язык. Выводы
// намеренно осторожные: проверка останавливается на первом успехе, поэтому
// «QUIC не сработал» может означать и «QUIC закрыт», и «до него не дошло».
func checkVerdict(outcomes []checkOutcome) []string {
	if len(outcomes) == 0 {
		return nil
	}

	var (
		quicTotal, quicOK int
		h2Total           int
		winner            *checkOutcome
	)
	for i := range outcomes {
		out := outcomes[i]
		switch {
		case out.useHTTP2:
			h2Total++
		default:
			quicTotal++
			if out.ok {
				quicOK++
			}
		}
		if out.ok && winner == nil {
			winner = &outcomes[i]
		}
	}

	if winner == nil {
		switch {
		case quicTotal > 0 && h2Total > 0:
			return []string{
				"ни UDP/QUIC, ни TCP/HTTP-2 до Cloudflare не проходят.",
				"Скорее всего, провайдер блокирует адреса Cloudflare целиком — обходом на стороне клиента это не обойти. Стоит попробовать IPv6 (флаг -6 в usque и «Использовать IPv6» в LuCI).",
			}
		case quicTotal > 0:
			return []string{
				"по UDP не прошла ни одна попытка: похоже, провайдер режет QUIC.",
				"Проверьте HTTP/2 — в LuCI режим «HTTP/2 (TCP 443)» или флаг --http2.",
			}
		default:
			return []string{
				"по TCP не прошла ни одна попытка: похоже, провайдер режет и HTTP/2 к Cloudflare.",
				"Проверьте QUIC (режим «QUIC / HTTP/3» в LuCI) и IPv6.",
			}
		}
	}

	first := outcomes[0]
	var lines []string
	if winner.useHTTP2 && !first.useHTTP2 && quicOK == 0 {
		lines = append(lines, "работает HTTP/2 (TCP), а QUIC не сработал: похоже, провайдер режет UDP — так и оставьте.")
	}
	if !winner.useHTTP2 && winner.port != first.port && first.port != 0 {
		lines = append(lines,
			fmt.Sprintf("работает порт %d, а порт %d нет: похоже, стандартный порт закрыт.", winner.port, first.port))
	}
	if winner.sni != "" && first.sni != "" && winner.sni != first.sni {
		lines = append(lines,
			fmt.Sprintf("работает имя %s, а %s нет: похоже, провайдер режет имена по SNI.", winner.sni, first.sni))
	}
	return lines
}

// checkCandidate выполняет одну попытку подключения к MASQUE и возвращает
// пустую строку при успехе либо причину отказа.
func checkCandidate(ctx context.Context, cand api.TunnelCandidate, keepalivePeriod time.Duration, initialPacketSize uint16, fragment *api.TLSFragmentConfig, timeout time.Duration) string {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	udpConn, tr, ipConn, rsp, err := api.ConnectTunnel(
		attemptCtx,
		cand.TLSConfig,
		internal.DefaultQuicConfig(keepalivePeriod, initialPacketSize),
		internal.ConnectURI,
		cand.Endpoint,
		cand.UseHTTP2,
		fragment,
	)

	var reason string
	switch {
	case err != nil:
		reason = err.Error()
	case rsp == nil:
		reason = "нет ответа"
	case rsp.StatusCode != http.StatusOK:
		reason = rsp.Status
	}

	if ipConn != nil {
		_ = ipConn.Close()
	}
	if tr != nil {
		_ = tr.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
	return reason
}

func init() {
	checkCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	checkCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	checkCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	checkCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	checkCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	checkCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection (default: auto with PMTU discovery)")
	checkCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	checkCmd.Flags().Bool("all", false, "Test every combination instead of stopping at the first working one")
	addBypassFlags(checkCmd)
	rootCmd.AddCommand(checkCmd)
}
