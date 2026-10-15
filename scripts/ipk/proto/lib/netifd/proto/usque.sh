#!/bin/sh
# netifd: протокол "usque" — Cloudflare WARP поверх MASQUE как обычный интерфейс OpenWrt.
#
# usque запускается как `usque nativetun -I` (сам адреса не ставит), а адреса и
# маршруты в netifd передаёт хук /usr/lib/usque/netifd-hook.sh при каждом
# успешном подключении тоннеля.
#
# Способ подключения (profile):
#   auto   — клиентский обход ТСПУ: usque сам перебирает адреса, порты и SNI
#            Cloudflare (--bypass), пока один не заработает (по умолчанию)
#   quic   — HTTP/3 (QUIC, UDP), порт connect_port или 443
#   h2     — HTTP/2 (TCP), порт connect_port или 443
#   manual — как заданы http2 и connect_port
#
# Опция bypass=1 включает обход ТСПУ и для явных способов quic/h2/manual:
# в этом случае usque перебирает комбинации, не ограничиваясь одним портом.

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

USQUE_BIN=/usr/bin/usque
USQUE_HOOK=/usr/lib/usque/netifd-hook.sh
USQUE_RUN=/usr/lib/usque/run.sh
USQUE_STATE=/var/run/usque
USQUE_DEFAULT_SNI=consumer-masque.cloudflareclient.com
USQUE_DEFAULT_H2_V4=162.159.198.2

# Подсети Cloudflare WARP/MASQUE, которые в режиме обхода уводятся мимо тоннеля
# (напрямую через прежний шлюз). Иначе после подъёма интерфейса перебор адресов
# ушёл бы сам в себя. Список должен покрывать пул из internal/bypass.go
# (BypassCIDRsV4 / BypassCIDRsV6) — держите их в синхроне.
USQUE_BYPASS_V4_CIDRS="162.159.192.0/24 162.159.193.0/24 162.159.195.0/24 162.159.197.0/24 162.159.198.0/24 162.159.204.0/24 162.159.239.0/24"
USQUE_BYPASS_V6_CIDRS="2606:4700:100::/48 2606:4700:102::/48 2606:4700:103::/48 2606:4700:105::/48"

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
	proto_config_add_boolean "bypass"
	proto_config_add_string "bypass_sni"
	proto_config_add_boolean "bypass_remember"
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

# маршрут до эндпоинта через прежний шлюз, чтобы тоннель не ушёл сам в себя.
# Все добавленные маршруты пишутся в <интерфейс>.routes и снимаются в usque_unpin.
usque_pin_route() { # интерфейс семейство назначение
	local interface="$1" fam="$2" dest="$3" r dev gw
	[ -n "$interface" ] || return 1

	r="$(ip $fam route get "${dest%%/*}" 2>/dev/null | head -n 1)"
	dev="$(echo "$r" | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
	gw="$(echo "$r" | sed -n 's/.* via \([^ ]*\).*/\1/p')"
	[ -n "$dev" ] || return 1

	if [ -n "$gw" ]; then
		ip $fam route replace "$dest" via "$gw" dev "$dev" || return 1
	else
		ip $fam route replace "$dest" dev "$dev" || return 1
	fi
	printf '%s %s\n' "$fam" "$dest" >> "$USQUE_STATE/$interface.routes"
}

# маршрут до конкретного адреса сервера
usque_pin_endpoint() { # интерфейс ep
	local interface="$1" ep="$2" fam="-4"
	case "$ep" in *:*) fam="-6" ;; esac
	usque_pin_route "$interface" "$fam" "$ep"
}

# в режиме обхода уводим мимо тоннеля весь пул адресов Cloudflare, чтобы
# перебор работал и после подъёма интерфейса (см. USQUE_BYPASS_*_CIDRS).
# Закрепляются оба семейства: перебор может добавить IPv6-комбинации, даже
# если -6 не задан (usque --bypass-ipv6-fallback).
usque_pin_bypass() { # интерфейс
	local interface="$1" cidr
	for cidr in $USQUE_BYPASS_V6_CIDRS; do
		usque_pin_route "$interface" "-6" "$cidr" ||
			logger -t usque "$interface: не удалось закрепить $cidr"
	done
	for cidr in $USQUE_BYPASS_V4_CIDRS; do
		usque_pin_route "$interface" "-4" "$cidr" ||
			logger -t usque "$interface: не удалось закрепить $cidr"
	done
}

usque_unpin() {
	local interface="$1" fam dest
	if [ -r "$USQUE_STATE/$interface.routes" ]; then
		while read -r fam dest; do
			[ -n "$dest" ] && ip $fam route del "$dest" 2>/dev/null
		done < "$USQUE_STATE/$interface.routes"
		rm -f "$USQUE_STATE/$interface.routes"
	fi
}

usque_cleanup() {
	local interface="$1"
	usque_unpin "$interface"
	rm -f "$USQUE_STATE/$interface.up" "$USQUE_STATE/$interface.cur" \
		"$USQUE_STATE/$interface.pid" "$USQUE_STATE/$interface.json" \
		"$USQUE_STATE/$interface.routes"
}

# Способ (quic/h2) здесь не запоминается: в режиме auto usque перебирает
# комбинации сам и держит победителя в памяти на время работы процесса, а
# удачную комбинацию обхода сохраняет по --bypass-state (галочка
# «Запоминать рабочую комбинацию обхода», файл рядом с config.json).

usque_fail() { # интерфейс КОД
	logger -t usque "$1: $2"
	proto_notify_error "$1" "$2"
	proto_block_restart "$1"
}

proto_usque_setup() {
	local interface="$1"
	local config profile endpoint endpoint_h2 defaultroute metric mtu connect_port sni http2 ipv6
	local tunnel_ipv4 tunnel_ipv6 keepalive reconnect_delay initial_packet_size
	local insecure connect_timeout bypass bypass_sni bypass_remember args
	local ifname cfg use_bypass cands c m p ep ep_h2 tmo i pid bypass_state

	json_get_vars config profile endpoint endpoint_h2 defaultroute metric mtu connect_port sni \
		http2 ipv6 tunnel_ipv4 tunnel_ipv6 keepalive reconnect_delay initial_packet_size \
		insecure connect_timeout bypass bypass_sni bypass_remember args

	[ -n "$config" ] || config=/etc/usque/config.json
	[ -n "$profile" ] || profile=auto
	[ -n "$defaultroute" ] || defaultroute=1
	[ -n "$mtu" ] || mtu=1280
	[ -n "$tunnel_ipv4" ] || tunnel_ipv4=1
	[ -n "$tunnel_ipv6" ] || tunnel_ipv6=1
	[ -n "$bypass_remember" ] || bypass_remember=1

	# Файл, в котором usque запоминает удачную комбинацию обхода: следующее
	# подключение начинается с неё. Лежит рядом с config.json, чтобы пережить
	# перезагрузку; галочка «Запоминать» заменяет путь на «-» (не запоминать).
	bypass_state="-"
	if [ "$bypass_remember" != 0 ]; then
		bypass_state="$(dirname "$config")/$interface.bypass"
		case "$bypass_state" in
		/*) ;;
		*) bypass_state="/etc/usque/$interface.bypass" ;;
		esac
	fi

	# «Авто» всегда включает клиентский обход ТСПУ; опция bypass=1 включает его и
	# для явных способов quic/h2/manual.
	use_bypass=0
	case "$profile" in auto) use_bypass=1 ;; esac
	[ "$bypass" = 1 ] && use_bypass=1

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

	# в режиме обхода usque сам перебирает адреса/порты/SNI, поэтому достаточно
	# одного запуска; иначе пробуем явный способ, заданный profile
	if [ "$use_bypass" = 1 ]; then
		cands="bypass"
	elif [ "$profile" = h2 ] || { [ "$profile" = manual ] && [ "$http2" = 1 ]; }; then
		cands="h2:${connect_port:-443}"
	else
		cands="quic:${connect_port:-443}"
	fi

	# время ожидания: в режиме обхода usque перебирает комбинации сам, поэтому
	# ждём весь перебор целиком (по умолчанию 90 с)
	tmo="$connect_timeout"
	if [ -z "$tmo" ]; then
		if [ "$use_bypass" = 1 ]; then tmo=90; else tmo=20; fi
	fi

	for c in $cands; do
		if [ "$c" = bypass ]; then
			m=bypass
			p="${connect_port:-443}"
		else
			m="${c%%:*}"
			p="${c##*:}"
		fi

		usque_unpin "$interface"
		rm -f "$USQUE_STATE/$interface.up"

		ep="$(usque_endpoint_ip "$cfg" "$ipv6" "$([ "$m" = h2 ] && echo h2 || echo quic)")"
		if [ "$defaultroute" = 1 ]; then
			if [ -n "$ep" ]; then
				usque_pin_endpoint "$interface" "$ep" ||
					logger -t usque "$interface: не удалось закрепить маршрут до $ep"
			else
				logger -t usque "$interface: в $config нет адреса эндпоинта"
			fi
			if [ "$use_bypass" = 1 ]; then
				# в обходе участвует и HTTP/2-адрес сервера
				ep_h2="$(usque_endpoint_ip "$cfg" "$ipv6" h2)"
				if [ -n "$ep_h2" ] && [ "$ep_h2" != "$ep" ]; then
					usque_pin_endpoint "$interface" "$ep_h2"
				fi
				usque_pin_bypass "$interface"
			fi
		fi

		printf 'mode=%s\nport=%s\nendpoint=%s\nsni=%s\nprofile=%s\n' \
			"$m" "$p" "$ep" "${sni:-$USQUE_DEFAULT_SNI}" "$profile" > "$USQUE_STATE/$interface.cur"

		# --always-reconnect обязателен: с -I usque не поднимает линк и не
		# ставит адреса, поэтому ядро не шлёт RS/DAD, которые иначе разбудили
		# бы тоннель. Адреса и маршруты ставит хук уже после подключения, так
		# что без этого флага первое подключение ждало бы трафик, которого до
		# подключения быть не может.
		set -- -c "$cfg" nativetun -n "$ifname" -I -m "$mtu" -P "$p" --always-reconnect
		if [ "$use_bypass" = 1 ]; then
			set -- "$@" --bypass
			# Запоминание рабочей комбинации между запусками (галочка в LuCI).
			set -- "$@" --bypass-state "$bypass_state"
			# Свой список SNI (пробел или запятая) полностью заменяет
			# встроенный — пригодится, когда домены Cloudflare блокируют.
			if [ -n "$bypass_sni" ]; then
				set -f
				for s in $(printf '%s' "$bypass_sni" | tr ', ' '  '); do
					[ -n "$s" ] && set -- "$@" --bypass-sni "$s"
				done
				set +f
			fi
		fi
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

		logger -t usque "$interface: $m не сработал"
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
