#!/bin/sh
# netifd: протокол "usque" — Cloudflare WARP поверх MASQUE как обычный интерфейс OpenWrt.
#
# usque запускается как `usque nativetun -I` (сам адреса не ставит), а адреса и
# маршруты в netifd передаёт хук /usr/lib/usque/netifd-hook.sh при каждом
# успешном подключении тоннеля.

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

USQUE_BIN=/usr/bin/usque
USQUE_HOOK=/usr/lib/usque/netifd-hook.sh
USQUE_STATE=/var/run/usque

proto_usque_init_config() {
	# своего устройства у протокола нет: его создаёт usque, имя usque-<интерфейс>
	no_device=1
	available=1

	proto_config_add_string "config"
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

# адрес эндпоинта Cloudflare из config.json с учётом режима (QUIC / HTTP2, IPv4 / IPv6)
usque_endpoint_ip() {
	local cfg="$1" v6="$2" h2="$3" key
	if [ "$h2" = 1 ]; then
		[ "$v6" = 1 ] && key=endpoint_h2_v6 || key=endpoint_h2_v4
	else
		[ "$v6" = 1 ] && key=endpoint_v6 || key=endpoint_v4
	fi
	jsonfilter -i "$cfg" -e "@.$key" 2>/dev/null
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

usque_cleanup() {
	local interface="$1" fam ep
	rm -f "$USQUE_STATE/$interface.up"
	if [ -r "$USQUE_STATE/$interface.route" ]; then
		read -r fam ep < "$USQUE_STATE/$interface.route"
		[ -n "$ep" ] && ip $fam route del "$ep" 2>/dev/null
		rm -f "$USQUE_STATE/$interface.route"
	fi
}

usque_fail() { # интерфейс КОД
	logger -t usque "$1: $2"
	proto_notify_error "$1" "$2"
	proto_block_restart "$1"
}

proto_usque_setup() {
	local interface="$1"
	local config defaultroute metric mtu connect_port sni http2 ipv6
	local tunnel_ipv4 tunnel_ipv6 keepalive reconnect_delay initial_packet_size
	local insecure connect_timeout args
	local ifname ep i

	json_get_vars config defaultroute metric mtu connect_port sni http2 ipv6 \
		tunnel_ipv4 tunnel_ipv6 keepalive reconnect_delay initial_packet_size \
		insecure connect_timeout args

	[ -n "$config" ] || config=/etc/usque/config.json
	[ -n "$mtu" ] || mtu=1280
	[ -n "$connect_timeout" ] || connect_timeout=20
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

	if [ "$defaultroute" = 1 ]; then
		ep="$(usque_endpoint_ip "$config" "$ipv6" "$http2")"
		if [ -n "$ep" ]; then
			usque_pin_endpoint "$interface" "$ep" ||
				logger -t usque "$interface: не удалось закрепить маршрут до $ep"
		else
			logger -t usque "$interface: в $config нет адреса эндпоинта"
		fi
	fi

	# окружение для хука (его запускает сам usque)
	proto_export "INTERFACE=$interface"
	proto_export "USQUE_STATE=$USQUE_STATE"
	proto_export "USQUE_MTU=$mtu"
	proto_export "USQUE_DEFAULTROUTE=${defaultroute:-0}"
	proto_export "USQUE_METRIC=$metric"
	if [ "$tunnel_ipv4" = 1 ]; then proto_export "USQUE_NO_IPV4=0"; else proto_export "USQUE_NO_IPV4=1"; fi
	if [ "$tunnel_ipv6" = 1 ]; then proto_export "USQUE_NO_IPV6=0"; else proto_export "USQUE_NO_IPV6=1"; fi

	set -- -c "$config" nativetun -n "$ifname" -I -m "$mtu"
	[ -n "$connect_port" ] && set -- "$@" -P "$connect_port"
	[ -n "$sni" ] && set -- "$@" -s "$sni"
	[ "$http2" = 1 ] && set -- "$@" --http2
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

	proto_run_command "$interface" "$USQUE_BIN" "$@"

	# ждём, пока хук сообщит об успешном подключении тоннеля
	i=0
	while [ "$i" -lt "$connect_timeout" ]; do
		[ -e "$USQUE_STATE/$interface.up" ] && return 0
		sleep 1
		i=$((i + 1))
	done

	usque_fail "$interface" CONNECT_TIMEOUT
	proto_kill_command "$interface"
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
