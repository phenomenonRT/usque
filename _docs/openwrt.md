# usque на OpenWrt: установка и интерфейс `usque`

Для OpenWrt собираются два пакета (`.ipk`):

| Пакет | Что делает |
|-------|------------|
| `usque_<версия>_<арх>_openwrt.ipk` | Сам клиент `/usr/bin/usque` + служба `/etc/init.d/usque` (SOCKS5 / HTTP-прокси / nativetun, настройка через `/etc/config/usque`). |
| `usque-proto_<версия>_all.ipk` | Протокол **`usque`** для netifd: WARP как обычный сетевой интерфейс OpenWrt (`network.<имя>.proto='usque'`) с настройкой в LuCI и UCI. Нужен установленный `usque`. |

Пакет `usque-proto` не зависит от архитектуры (`all`), `usque` нужно выбрать под ваш роутер.

## 1. Какой пакет `usque` выбрать

Выполните на роутере:

```sh
opkg print-architecture
```

| Архитектура OpenWrt | Суффикс пакета |
|---------------------|----------------|
| `x86_64` | `amd64` |
| `aarch64_*` | `arm64` |
| `arm_cortex-a*` (a7, a9, a15) | `armv7` |
| `arm_arm926ej-s`, `arm_arm1176jzf-s_vfp` и другие ARMv5/ARMv6 | `armv5` |
| `mipsel_*` (mipsel_24kc, mipsel_74kc …) | `mipsle` |
| `mips_*` (mips_24kc, mips_74kc …) | `mips` |
| `mips64_*` | `mips64` |
| `mips64el_*` | `mips64le` |

## 2. Установка

Скачайте нужные `.ipk` из релиза репозитория и скопируйте на роутер:

```sh
scp usque_*_<арх>_openwrt.ipk usque-proto_*_all.ipk root@192.168.1.1:/tmp/
```

На роутере:

```sh
opkg update
opkg install kmod-tun            # TUN нужен для режима интерфейса
opkg install /tmp/usque_*_openwrt.ipk
opkg install /tmp/usque-proto_*_all.ipk
/etc/init.d/network restart       # netifd подхватит новый протокол
```

> `ip` (пакет `ip-tiny` или `ip-full`) в обычных сборках OpenWrt уже есть. Если нет: `opkg install ip-full`.

## 3. Регистрация в Cloudflare WARP

Один раз создайте конфиг (ключ устройства и адреса тоннеля):

```sh
mkdir -p /etc/usque
usque -c /etc/usque/config.json register
```

Если `register` не отвечает из вашей сети, выполните его на другом компьютере или через другой канал и скопируйте получившийся `config.json` в `/etc/usque/`.

## 4. Интерфейс WARP (netifd)

### Через LuCI

1. **Network → Interfaces → Add new interface…**
2. Имя: `warp` (не длиннее 9 символов), протокол: **Cloudflare WARP (usque / MASQUE)**.
3. Укажите файл конфигурации (по умолчанию `/etc/usque/config.json`), при необходимости откройте *Advanced Settings*.
4. На вкладке *Firewall Settings* привяжите интерфейс к зоне (см. раздел 5).
5. **Save & Apply**.

### Через UCI

```sh
uci set network.warp=interface
uci set network.warp.proto='usque'
uci set network.warp.config='/etc/usque/config.json'
uci set network.warp.defaultroute='0'
uci commit network
ifup warp
```

Проверка:

```sh
ifstatus warp
ip addr show usque-warp
logread -e usque
```

Устройство называется `usque-<имя интерфейса>` (до 15 символов).

### Параметры интерфейса

| Опция UCI | По умолчанию | Описание |
|-----------|--------------|----------|
| `config` | `/etc/usque/config.json` | Конфиг, созданный командой `usque register`. |
| `defaultroute` | `0` | `1` — пустить весь трафик роутера через WARP (маршрут до эндпоинта Cloudflare добавляется через прежний шлюз автоматически). |
| `dns` | не задан | Список DNS-серверов для интерфейса, например `1.1.1.1`. |
| `mtu` | `1280` | MTU тоннеля (менять не рекомендуется). |
| `connect_port` | `443` | Порт подключения MASQUE. |
| `sni` | по умолчанию usque | Свой SNI. |
| `http2` | `0` | `1` — HTTP/2 поверх TCP+TLS вместо HTTP/3 (QUIC). Полезно, если UDP режется. |
| `ipv6` | `0` | `1` — подключаться к эндпоинту по IPv6. |
| `tunnel_ipv4` / `tunnel_ipv6` | `1` / `1` | Выдавать ли внутри тоннеля IPv4 / IPv6-адрес. |
| `keepalive` | `30s` | Период keepalive. |
| `reconnect_delay` | `1s` | Пауза между попытками переподключения. |
| `initial_packet_size` | авто | Размер первого пакета. |
| `insecure` | `0` | Не проверять сертификат эндпоинта (только для отладки). |
| `connect_timeout` | `20` | Сколько секунд ждать подключения тоннеля при старте. |
| `args` | пусто | Дополнительные аргументы для `usque nativetun`. |

## 5. Файрвол и маршрутизация

Чтобы клиенты LAN выходили в интернет через WARP, создайте зону для интерфейса:

```sh
uci add firewall zone
uci set firewall.@zone[-1].name='warp'
uci set firewall.@zone[-1].network='warp'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].mtu_fix='1'
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='lan'
uci set firewall.@forwarding[-1].dest='warp'
uci commit firewall
/etc/init.d/firewall restart
```

Какой трафик идёт в тоннель, решает маршрутизация:

- **Весь трафик** — `uci set network.warp.defaultroute='1'` (и `ifup warp`).
- **Только нужные сети** — оставьте `defaultroute='0'` и добавьте статический маршрут:
  ```sh
  uci add network route
  uci set network.@route[-1].interface='warp'
  uci set network.@route[-1].target='203.0.113.0/24'
  uci commit network && /etc/init.d/network reload
  ```
- **По источнику (отдельные устройства)** — политика маршрутизации (`pbr`, `mwan3` или `ip rule`) с таблицей, в которой маршрут по умолчанию идёт на `usque-warp`.

Сам usque маршруты не расставляет, в режиме интерфейса это делает netifd.

## 6. Служба `usque` (без интерфейса)

Пакет `usque` также содержит независимую службу (SOCKS5 / HTTP-прокси / nativetun), настройка в `/etc/config/usque`:

```sh
uci set usque.main.enabled=1 && uci commit usque
/etc/init.d/usque enable && /etc/init.d/usque start
```

Не включайте службу и интерфейс `usque` одновременно на одном `config.json`: оба будут занимать одно устройство WARP.

## 7. Если не работает

| Симптом | Что проверить |
|---------|---------------|
| В LuCI нет протокола `usque` | `/etc/init.d/network restart`, очистить кэш браузера. |
| `NO_TUN` в `logread` | `opkg install kmod-tun`, затем `modprobe tun`. |
| `NO_CONFIG` | Файл из опции `config` не существует: выполните `usque ... register`. |
| `CONNECT_TIMEOUT` | Тоннель не поднялся за `connect_timeout` секунд. Смотрите `logread -e usque`; попробуйте `http2=1`, другой `connect_port`, увеличьте таймаут. |
| Интерфейс поднят, трафика нет | Зона файрвола, маршруты (`ip route`, `ip rule`), `masq` на зоне `warp`. |
| Пропал интернет после `defaultroute=1` | Проверьте маршрут до эндпоинта: `ip route get <endpoint_v4 из config.json>` должен идти через WAN, а не через `usque-warp`. |

## 8. Удаление

```sh
ifdown warp
uci delete network.warp && uci commit network
opkg remove usque-proto usque
```
