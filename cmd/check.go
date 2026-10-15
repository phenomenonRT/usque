package cmd

import (
	"context"
	"fmt"
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

		cmd.Printf("Проверка подключения: %d комбинаций, таймаут одной попытки %s\n", len(candidates), timeout)
		if len(plan.Candidates) == 0 {
			cmd.Println("(обход не включён — проверяется только текущий способ)")
		}

		okCount := 0
		firstOK := ""
		for i, cand := range candidates {
			attemptCtx, cancel := context.WithTimeout(ctx, timeout)
			udpConn, tr, ipConn, rsp, err := api.ConnectTunnel(
				attemptCtx,
				cand.TLSConfig,
				internal.DefaultQuicConfig(keepalivePeriod, plan.InitialPacketSize),
				internal.ConnectURI,
				cand.Endpoint,
				cand.UseHTTP2,
				plan.Fragment,
			)
			cancel()

			var reason string
			switch {
			case err != nil:
				reason = err.Error()
			case rsp == nil:
				reason = "нет ответа"
			case rsp.StatusCode != 200:
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

			if reason == "" {
				okCount++
				if firstOK == "" {
					firstOK = cand.Label
				}
				cmd.Printf("[%d/%d] OK   %s\n", i+1, len(candidates), cand.Label)
				if !testAll {
					break
				}
				continue
			}
			cmd.Printf("[%d/%d] нет  %s — %s\n", i+1, len(candidates), cand.Label, reason)
		}

		if okCount == 0 {
			cmd.Println("Результат: ни одна комбинация не сработала.")
			return fmt.Errorf("не удалось подключиться")
		}
		cmd.Printf("Результат: работает %d из %d. Рабочая комбинация: %s\n", okCount, len(candidates), firstOK)
		return nil
	},
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
