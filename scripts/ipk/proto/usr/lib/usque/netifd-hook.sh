#!/bin/sh
# Хук usque (--on-connect / --on-disconnect) для протокола netifd "usque".
# Окружение задают usque (USQUE_EVENT, USQUE_IFACE, USQUE_IPV4, USQUE_IPV6)
# и /lib/netifd/proto/usque.sh (INTERFACE, USQUE_STATE, USQUE_MTU, USQUE_*).

. /lib/functions.sh
. /lib/netifd/netifd-proto.sh

[ -n "$INTERFACE" ] || exit 0

case "$USQUE_EVENT" in
connect) ;;
disconnect)
	rm -f "${USQUE_STATE:-/var/run/usque}/$INTERFACE.up"
	exit 0
	;;
*) exit 0 ;;
esac

[ -n "$USQUE_IFACE" ] || exit 0

# без -I usque сам ставил бы MTU и поднимал линк; теперь это здесь
ip link set dev "$USQUE_IFACE" mtu "${USQUE_MTU:-1280}" up 2>/dev/null

proto_init_update "$USQUE_IFACE" 1

have4=0
have6=0
if [ "$USQUE_NO_IPV4" != 1 ] && [ -n "$USQUE_IPV4" ]; then
	proto_add_ipv4_address "$USQUE_IPV4" 32
	have4=1
fi
if [ "$USQUE_NO_IPV6" != 1 ] && [ -n "$USQUE_IPV6" ]; then
	proto_add_ipv6_address "$USQUE_IPV6" 128
	have6=1
fi

# весь трафик в тоннель: две половины вместо 0/0, чтобы не трогать маршрут WAN
if [ "$USQUE_DEFAULTROUTE" = 1 ]; then
	if [ "$have4" = 1 ]; then
		proto_add_ipv4_route 0.0.0.0 1 "" "" "$USQUE_METRIC"
		proto_add_ipv4_route 128.0.0.0 1 "" "" "$USQUE_METRIC"
	fi
	if [ "$have6" = 1 ]; then
		proto_add_ipv6_route :: 1 "" "$USQUE_METRIC"
		proto_add_ipv6_route 8000:: 1 "" "$USQUE_METRIC"
	fi
fi

proto_send_update "$INTERFACE"

mkdir -p "${USQUE_STATE:-/var/run/usque}"
: > "${USQUE_STATE:-/var/run/usque}/$INTERFACE.up"
exit 0
