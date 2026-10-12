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
3. В верхней части окна интерфейса находится **панель состояния**:
   - состояние (подключено / подключаюсь / остановлено);
   - **к какому серверу, порту и по какому протоколу идёт подключение**, SNI и адрес в тоннеле;
   - кнопки **Старт, Стоп, Перезапуск, Обновить** (Стоп работает всегда, даже если интерфейс завис в ошибке);
   - **«Зарегистрировать»**, если файла настроек WARP ещё нет, и «Перерегистрация» (старый конфиг сохраняется как `.bak`);
   - раскрывающийся **журнал usque**, где видно, почему не подключилось.
4. Ниже выберите **Способ подключения** (по умолчанию «Авто»), при необходимости порт, SNI и адрес сервера. Подробности в разделе 4.1.
5. На вкладке *Firewall Settings* привяжите интерфейс к зоне (см. раздел 5).
6. **Save & Apply**.

> Родная кнопка **Stop** в списке интерфейсов LuCI неактивна, пока интерфейс не поднят. Это поведение самого LuCI, и пакет его не меняет. Используйте кнопку «Стоп» в панели внутри окна интерфейса.

Если панель показывает «Панель недоступна», выполните `/etc/init.d/rpcd restart` и войдите в LuCI заново (rpcd читает плагины только при запуске).

### 4.1. Настройка обхода блокировок (ТСПУ)

Весь трафик MASQUE идёт к Cloudflare. Если сеть режет QUIC (UDP) или стандартное имя, подключение не поднимается (`CONNECT_TIMEOUT`). Выбирается один из способов:

| Способ | Что делает |
|--------|------------|
| **Авто** (по умолчанию) | Перебирает способы по очереди, пока один не заработает, и запоминает его (`/etc/usque/last-<интерфейс>`). Порядок: порт, заданный вами, последний удачный, затем QUIC 443, HTTP/2 TCP 443, QUIC 4443, 8443, 500, 4500, 1701, 8095. |
| QUIC / HTTP/3 (UDP) | Только QUIC, порт из поля «Порт сервера» (по умолчанию 443). |
| HTTP/2 (TCP 443) | Только HTTP/2 по TCP. Подходит, когда режется UDP. |
| Вручную | Берутся флаг `http2` и порт из полей ниже. |

Порты UDP 443 (основной), 500, 1701, 4500, 4443, 8443, 8095 и TCP 443 для HTTP/2 указаны в документации Cloudflare ([WARP with firewall](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/)); адреса MASQUE: `162.159.197.0/24`.

Поля, которые можно менять:
- **Порт сервера:** выпадающий список портов или своё значение.
- **SNI:** имя в TLS-рукопожатии. Автор usque сообщает, что подойдёт любое имя и соединение продолжит работать. Готовые варианты: `consumer-masque.cloudflareclient.com` (стандартный), `zt-masque.cloudflareclient.com` (рекомендует автор usque), `www.cloudflare.com`, `one.one.one.one`.
- **Адрес сервера (QUIC)** и **Адрес сервера (HTTP/2)**: IP-адреса вместо взятых из `config.json`. Пусто означает «из config.json» (для HTTP/2 по умолчанию `162.159.198.2`).

> Какая комбинация проходит через ваш провайдер и ТСПУ, заранее сказать нельзя: это зависит от сети и со временем меняется. Режим «Авто» нужен как раз для того, чтобы подобрать её на месте. Если ничего не подошло, пришлите содержимое журнала, и по нему можно понять, где обрывается соединение.

### Через UCI

```sh
uci set network.warp=interface
uci set network.warp.proto='usque'
uci set network.warp.config='/etc/usque/config.json'
uci set network.warp.profile='auto'
uci set network.warp.sni='zt-masque.cloudflareclient.com'
uci commit network
ifup warp
```

Проверка:

```sh
ifstatus warp
ip addr show usque-warp
cat /var/run/usque/warp.log      # журнал usque (в RAM)
logread -e usque                  # сообщения netifd-протокола
```

Устройство называется `usque-<имя интерфейса>` (до 15 символов).

### Параметры интерфейса

| Опция UCI | По умолчанию | Описание |
|-----------|--------------|----------|
| `config` | `/etc/usque/config.json` | Конфиг, созданный командой `usque register`. |
| `profile` | `auto` | Способ подключения: `auto`, `quic`, `h2`, `manual` (см. 4.1). |
| `connect_port` | `443` | Порт сервера. В `auto` пробуется первым. |
| `sni` | по умолчанию usque | Свой SNI. |
| `endpoint` | из config.json | IP сервера для QUIC. |
| `endpoint_h2` | из config.json | IP сервера для HTTP/2. |
| `http2` | `0` | Только для `profile=manual`: `1` — HTTP/2 вместо QUIC. |
| `ipv6` | `0` | `1` — подключаться к серверу по IPv6. |
| `defaultroute` | `1` | Общая опция LuCI «Use default gateway»: `1` — весь трафик роутера через WARP (маршрут до сервера Cloudflare добавляется через прежний шлюз автоматически), `0` — маршруты задаёте сами. |
| `dns` | не задан | Общая опция LuCI «Use custom DNS servers». |
| `mtu` | `1280` | MTU тоннеля (менять не рекомендуется). |
| `tunnel_ipv4` / `tunnel_ipv6` | `1` / `1` | Выдавать ли внутри тоннеля IPv4 / IPv6-адрес. |
| `keepalive` | `30s` | Период keepalive. |
| `reconnect_delay` | `1s` | Пауза между попытками переподключения. |
| `initial_packet_size` | авто | Размер первого пакета. |
| `insecure` | `0` | Не проверять сертификат сервера (только для отладки). |
| `connect_timeout` | `10` (`auto`), `20` (остальные) | Сколько секунд ждать подключения при каждой попытке. |
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

- **Весь трафик** — по умолчанию (`defaultroute='1'`).
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
| Панель состояния пишет «недоступна» | `/etc/init.d/rpcd restart`, затем войти в LuCI заново. |
| `NO_TUN` в `logread` | `opkg install kmod-tun`, затем `modprobe tun`. |
| `NO_CONFIG` | Файл из опции `config` не существует: выполните `usque ... register`. |
| `CONNECT_TIMEOUT` | Ни один способ не подключился. Откройте журнал в панели интерфейса (или `/var/run/usque/<имя>.log`). Проверьте `profile=auto`, другой SNI, адрес сервера, увеличьте `connect_timeout`. |
| Интерфейс поднят, трафика нет | Зона файрвола, маршруты (`ip route`, `ip rule`), `masq` на зоне `warp`. |
| Пропал интернет после `defaultroute=1` | Проверьте маршрут до эндпоинта: `ip route get <endpoint_v4 из config.json>` должен идти через WAN, а не через `usque-warp`. |

## 8. Удаление

```sh
ifdown warp
uci delete network.warp && uci commit network
opkg remove usque-proto usque
```
