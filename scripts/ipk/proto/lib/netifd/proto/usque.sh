#!/bin/sh
# netifd: протокол "usque" — Cloudflare WARP поверх MASQUE как обычный интерфейс OpenWrt.
#
# usque запускается как `usque nativetun -I` (сам адреса не ставит), а адреса и
# маршруты в netifd передаёт хук /usr/lib/usque/netifd-hook.sh при каждом
# успешном подключении тоннеля.
#
# Способ подключения (profile):
#   auto   — перебирать способы, пока один не заработает (по умолчанию)
#   quic   — HTTP/3 (QUIC, UDP), порт connect_port или 443
#   h2     — HTTP/2 (TCP), порт connect_port или 443
#   manual — как заданы http2 и connect_port

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

USQUE_BIN=/usr/bin/usque
USQUE_HOOK=/usr/lib/usque/netifd-hook.sh
USQUE_RUN=/usr/lib/usque/run.sh
USQUE_STATE=/var/run/usque
USQUE_PERSIST=/etc/usque
USQUE_DEFAULT_SNI=consumer-masque.cloudflareclient.com
USQUE_DEFAULT_H2_V4=162.159.198.2

# порядок перебора в режиме auto после порта пользователя и последнего удачного способа;
# порты — по документации Cloudflare (WARP: firewall): UDP 443 основной, запасные
# UDP 4443 8443 500 4500 1701 8095, HTTP/2 — TCP 443
USQUE_AUTO_ORDER="quic:443 h2:443 quic:4443 quic:8443 quic:500 quic:4500 quic:1701 quic:8095"

proto_usque_init_config() {
	# своего устройства у протокола нет: его создаёт usque, имя usque-<интерфейс>
	no_device=1
	available=1

	proto_config_add_string "config"
	proto_config_add_string "profile"
	proto_config_add_string "endpoint"
	proto_config_add_string "endpoint_h2"
	proto_config_add_boolean "defaultroute"
	proto_config_add_int "metric"
	proto_config_add_int "mtu"
	proto_config_add_int "connect_port"
	proto_config_add_string "sni"
	proto_config_add_boolean "http2"
	proto_config_add_boolean "ipv6"
	proto_config_add_boolean "tunnel_ipv4"
	proto_config_add_boolean "tunnel_ipv6"
	proto_config_add_string "keepalive"
	proto_config_add_string "reconnect_delay"
	proto_config_add_int "initial_packet_size"
	proto_config_add_boolean "insecure"
	proto_config_add_int "connect_timeout"
	proto_config_add_string "args"
}

# "30" -> "30s", "1m" остаётся как есть
usque_duration() {
	case "$1" in
	*[!0-9]*) echo "$1" ;;
	*) echo "${1}s" ;;
	esac
}

# адрес состоит только из символов IPv4/IPv6
usque_ip_ok() {
	case "$1" in
	"" | *[!0-9a-fA-F:.]*) return 1 ;;
	esac
	return 0
}

# Копия config.json с подменённым адресом сервера (оригинал не трогаем).
# usque_effective_config <интерфейс> <config> <endpoint> <endpoint_h2> → путь к файлу
usque_effective_config() {
	local interface="$1" cfg="$2" ep="$3" eph2="$4"
	local out="$USQUE_STATE/$interface.json" pair addr k keys

	if [ -z "$ep" ] && [ -z "$eph2" ]; then
		echo "$cfg"
		return 0
	fi

	umask 077
	cp "$cfg" "$out" || return 1
	chmod 600 "$out"

	for pair in "quic:$ep" "h2:$eph2"; do
		addr="${pair#*:}"
		[ -n "$addr" ] || continue
		usque_ip_ok "$addr" || return 1
		case "$pair" in
		quic:*)
			case "$addr" in *:*) keys="endpoint_v6" ;; *) keys="endpoint_v4" ;; esac
			;;
		*)
			case "$addr" in *:*) keys="endpoint_h2_v6" ;; *) keys="endpoint_h2_v4" ;; esac
			;;
		esac
		for k in $keys; do
			if grep -q "\"$k\"" "$out"; then
				sed -i -E "s/(\"$k\"[[:space:]]*:[[:space:]]*\")[^\"]*\"/\1$addr\"/" "$out"
			else
				sed -i "1s/^{/{\"$k\":\"$addr\",/" "$out"
			fi
		done
	done
	echo "$out"
}

# адрес эндпоинта Cloudflare из конфига для режима quic|h2 и семейства IPv4/IPv6
usque_endpoint_ip() {
	local cfg="$1" v6="$2" mode="$3" key val
	if [ "$mode" = h2 ]; then
		[ "$v6" = 1 ] && key=endpoint_h2_v6 || key=endpoint_h2_v4
	else
		[ "$v6" = 1 ] && key=endpoint_v6 || key=endpoint_v4
	fi
	val="$(jsonfilter -i "$cfg" -e "@.$key" 2>/dev/null)"
	[ -n "$val" ] || { [ "$key" = endpoint_h2_v4 ] && val="$USQUE_DEFAULT_H2_V4"; }
	echo "$val"
}

# маршрут до эндпоинта через прежний шлюз, чтобы тоннель не ушёл сам в себя
usque_pin_endpoint() {
	local interface="$1" ep="$2" fam="-4" r dev gw
	case "$ep" in *:*) fam="-6" ;; esac

	r="$(ip $fam route get "$ep" 2>/dev/null | head -n 1)"
	dev="$(echo "$r" | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
	gw="$(echo "$r" | sed -n 's/.* via \([^ ]*\).*/\1/p')"
	[ -n "$dev" ] || return 1

	if [ -n "$gw" ]; then
		ip $fam route replace "$ep" via "$gw" dev "$dev" || return 1
	else
		ip $fam route replace "$ep" dev "$dev" || return 1
	fi
	echo "$fam $ep" > "$USQUE_STATE/$interface.route"
}

usque_unpin() {
	local interface="$1" fam ep
	if [ -r "$USQUE_STATE/$interface.route" ]; then
		read -r fam ep < "$USQUE_STATE/$interface.route"
		[ -n "$ep" ] && ip $fam route del "$ep" 2>/dev/null
		rm -f "$USQUE_STATE/$interface.route"
	fi
}

usque_cleanup() {
	local interface="$1"
	usque_unpin "$interface"
	rm -f "$USQUE_STATE/$interface.up" "$USQUE_STATE/$interface.cur" \
		"$USQUE_STATE/$interface.pid" "$USQUE_STATE/$interface.json"
}

# способы для режима auto: порт пользователя, последний удачный, затем общий порядок
usque_auto_candidates() {
	local interface="$1" port="$2" first="" last=""
	[ -n "$port" ] && first="quic:$port"
	[ -r "$USQUE_PERSIST/last-$interface" ] && last="$(head -n 1 "$USQUE_PERSIST/last-$interface")"
	echo "$first $last $USQUE_AUTO_ORDER" | tr ' ' '\n' |
		grep -E '^(quic|h2):[0-9]+$' | awk '!seen[$0]++' | tr '\n' ' '
}

# запомнить удачный способ (на флеш пишем только при изменении)
usque_remember() {
	local f="$USQUE_PERSIST/last-$1"
	[ "$(cat "$f" 2>/dev/null)" = "$2" ] && return 0
	mkdir -p "$USQUE_PERSIST"
	echo "$2" > "$f"
}

usque_fail() { # интерфейс КОД
	logger -t usque "$1: $2"
	proto_notify_error "$1" "$2"
	proto_block_restart "$1"
}

proto_usque_setup() {
	local interface="$1"
	local config profile endpoint endpoint_h2 defaultroute metric mtu connect_port sni http2 ipv6
	local tunnel_ipv4 tunnel_ipv6 keepalive reconnect_delay initial_packet_size
	local insecure connect_timeout args
	local ifname cfg cands c m p ep tmo i pid

	json_get_vars config profile endpoint endpoint_h2 defaultroute metric mtu connect_port sni \
		http2 ipv6 tunnel_ipv4 tunnel_ipv6 keepalive reconnect_delay initial_packet_size \
		insecure connect_timeout args

	[ -n "$config" ] || config=/etc/usque/config.json
	[ -n "$profile" ] || profile=auto
	[ -n "$defaultroute" ] || defaultroute=1
	[ -n "$mtu" ] || mtu=1280
	[ -n "$tunnel_ipv4" ] || tunnel_ipv4=1
	[ -n "$tunnel_ipv6" ] || tunnel_ipv6=1

	ifname="usque-$interface"
	[ "${#ifname}" -le 15 ] || { usque_fail "$interface" IFNAME_TOO_LONG; return 1; }
	[ -x "$USQUE_BIN" ] || { usque_fail "$interface" NO_BINARY; return 1; }
	[ -r "$config" ] || { usque_fail "$interface" NO_CONFIG; return 1; }

	[ -c /dev/net/tun ] || modprobe tun 2>/dev/null
	[ -c /dev/net/tun ] || { usque_fail "$interface" NO_TUN; return 1; }

	mkdir -p "$USQUE_STATE"
	usque_cleanup "$interface"

	cfg="$(usque_effective_config "$interface" "$config" "$endpoint" "$endpoint_h2")" ||
		{ usque_fail "$interface" BAD_ENDPOINT; return 1; }

	# окружение для хука (его запускает сам usque)
	proto_export "INTERFACE=$interface"
	proto_export "USQUE_STATE=$USQUE_STATE"
	proto_export "USQUE_MTU=$mtu"
	proto_export "USQUE_DEFAULTROUTE=$defaultroute"
	proto_export "USQUE_METRIC=$metric"
	if [ "$tunnel_ipv4" = 1 ]; then proto_export "USQUE_NO_IPV4=0"; else proto_export "USQUE_NO_IPV4=1"; fi
	if [ "$tunnel_ipv6" = 1 ]; then proto_export "USQUE_NO_IPV6=0"; else proto_export "USQUE_NO_IPV6=1"; fi

	case "$profile" in
	quic) cands="quic:${connect_port:-443}" ;;
	h2) cands="h2:${connect_port:-443}" ;;
	manual)
		if [ "$http2" = 1 ]; then cands="h2:${connect_port:-443}"; else cands="quic:${connect_port:-443}"; fi
		;;
	*) cands="$(usque_auto_candidates "$interface" "$connect_port")" ;;
	esac

	# время ожидания одной попытки; в auto по умолчанию короче, чтобы перебор не затягивался
	tmo="$connect_timeout"
	if [ -z "$tmo" ]; then
		case "$profile" in
		quic | h2 | manual) tmo=20 ;;
		*) tmo=10 ;;
		esac
	fi

	for c in $cands; do
		m="${c%%:*}"
		p="${c##*:}"

		usque_unpin "$interface"
		rm -f "$USQUE_STATE/$interface.up"

		ep="$(usque_endpoint_ip "$cfg" "$ipv6" "$m")"
		if [ "$defaultroute" = 1 ]; then
			if [ -n "$ep" ]; then
				usque_pin_endpoint "$interface" "$ep" ||
					logger -t usque "$interface: не удалось закрепить маршрут до $ep"
			else
				logger -t usque "$interface: в $config нет адреса эндпоинта"
			fi
		fi

		printf 'mode=%s\nport=%s\nendpoint=%s\nsni=%s\nprofile=%s\n' \
			"$m" "$p" "$ep" "${sni:-$USQUE_DEFAULT_SNI}" "$profile" > "$USQUE_STATE/$interface.cur"

		set -- -c "$cfg" nativetun -n "$ifname" -I -m "$mtu" -P "$p"
		[ "$m" = h2 ] && set -- "$@" --http2
		[ -n "$sni" ] && set -- "$@" -s "$sni"
		[ "$ipv6" = 1 ] && set -- "$@" -6
		[ "$tunnel_ipv4" = 1 ] || set -- "$@" -F
		[ "$tunnel_ipv6" = 1 ] || set -- "$@" -S
		[ -n "$keepalive" ] && set -- "$@" -k "$(usque_duration "$keepalive")"
		[ -n "$reconnect_delay" ] && set -- "$@" -r "$(usque_duration "$reconnect_delay")"
		[ -n "$initial_packet_size" ] && set -- "$@" -i "$initial_packet_size"
		[ "$insecure" = 1 ] && set -- "$@" --insecure
		set -- "$@" --on-connect "$USQUE_HOOK" --on-disconnect "$USQUE_HOOK"
		if [ -n "$args" ]; then
			set -f
			# shellcheck disable=SC2086
			set -- "$@" $args
			set +f
		fi

		logger -t usque "$interface: пробую $m, порт $p, сервер ${ep:-?}"
		proto_run_command "$interface" "$USQUE_RUN" "$interface" "$USQUE_BIN" "$@"

		# ждём, пока хук сообщит об успешном подключении тоннеля
		i=0
		while [ "$i" -lt "$tmo" ]; do
			[ -e "$USQUE_STATE/$interface.up" ] && {
				usque_remember "$interface" "$c"
				logger -t usque "$interface: подключено ($m, порт $p)"
				return 0
			}
			# usque завершился сам (например, неверные аргументы) — не ждём таймаут
			if [ "$i" -ge 2 ]; then
				pid="$(cat "$USQUE_STATE/$interface.pid" 2>/dev/null)"
				[ -n "$pid" ] && [ ! -d "/proc/$pid" ] && break
			fi
			sleep 1
			i=$((i + 1))
		done

		logger -t usque "$interface: $m:$p не сработал"
		proto_kill_command "$interface"
		sleep 1
	done

	usque_fail "$interface" CONNECT_TIMEOUT
	usque_cleanup "$interface"
	return 1
}

proto_usque_teardown() {
	local interface="$1"
	proto_kill_command "$interface"
	usque_cleanup "$interface"
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol usque
}
