#!/bin/sh
# Сборка .ipk для Keenetic (OPKG / Entware, установка в /opt).
# Использование: scripts/build-keenetic.sh [версия]
# Результат: dist/keenetic/usque_<версия>_<арх>_keenetic.ipk (клиент + служба
# /opt/etc/init.d/S99usque) и отдельные бинарники usque_<версия>_linux_<арх>.
# SKIP_BUILD=1 — не компилировать, взять готовые dist/bin/usque-linux-<арх>.
set -eu
cd "$(dirname "$0")/.."
VER="${1:-$(date -u +%Y.%m.%d)}"
VER="${VER#v}"
OUT="$PWD/dist/keenetic"; BIN="$PWD/dist/bin"
mkdir -p "$OUT" "$BIN"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

MOD="github.com/Diniboy1123/usque"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

build() { # имя GOARCH [ENV...]
  name="$1"; arch="$2"; shift 2
  echo "==> go build linux/$name"
  env CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$@" \
    go build -trimpath \
      -ldflags "-s -w -X $MOD/cmd.version=$VER -X $MOD/cmd.commit=$COMMIT -X $MOD/cmd.date=$DATE" \
      -o "$BIN/usque-linux-$name" .
}

if [ "${SKIP_BUILD:-0}" != 1 ]; then
  build mipsle mipsle GOMIPS=softfloat   # большинство Keenetic: MT7621/MT7628/MT7620
  build mips   mips   GOMIPS=softfloat   # старые MIPS big-endian (mipssf-k3.4)
  build armv5  arm    GOARM=5            # ARM soft-float: годится и для armv5sf, и для armv7sf
  build arm64  arm64                     # aarch64 (Hero KN-1012, Peak KN-2710 и другие новые)
fi

TAR="tar --owner=0 --group=0 --numeric-owner --format=gnu"

mk() { # имя-в-пакете строка-Architecture-для-opkg имя-бинарника
  name="$1"; earch="$2"; binname="$3"
  bin="$BIN/usque-linux-$binname"
  [ -f "$bin" ] || { echo "нет $bin — пропуск" >&2; return 0; }
  w="$T/$name"; mkdir -p "$w/control" "$w/data/opt/bin" "$w/data/opt/etc/init.d" "$w/data/opt/etc/usque"

  install -m 755 "$bin"                      "$w/data/opt/bin/usque"
  install -m 755 scripts/keenetic/S99usque   "$w/data/opt/etc/init.d/S99usque"
  install -m 644 scripts/keenetic/usque.conf "$w/data/opt/etc/usque/usque.conf"

  cat > "$w/control/postinst" <<'EOS'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
mkdir -p /opt/etc/usque
echo "usque установлен (Keenetic / Entware). Дальше:"
echo "  1) usque -c /opt/etc/usque/config.json register"
echo "  2) режим и обход ТСПУ задаются в /opt/etc/usque/usque.conf (MODE, ENABLED, ARGS)"
echo "  3) /opt/etc/init.d/S99usque start"
exit 0
EOS
  cat > "$w/control/prerm" <<'EOS'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/opt/etc/init.d/S99usque stop 2>/dev/null
exit 0
EOS
  printf '/opt/etc/usque/usque.conf\n' > "$w/control/conffiles"
  chmod 755 "$w/control/postinst" "$w/control/prerm"

  size=$(du -sk "$w/data" | cut -f1); size=$((size*1024))
  cat > "$w/control/control" <<EOS
Package: usque
Version: $VER
Source: usque
Section: net
Priority: optional
Maintainer: usque
Architecture: $earch
Installed-Size: $size
License: MIT
Description: Cloudflare WARP client over MASQUE for Keenetic / Entware (binary for $earch)
EOS

  ( cd "$w/control" && $TAR -czf ../control.tar.gz ./control ./postinst ./prerm ./conffiles )
  ( cd "$w/data"    && $TAR -czf ../data.tar.gz . )
  echo "2.0" > "$w/debian-binary"
  f="$OUT/usque_${VER}_${name}_keenetic.ipk"
  ( cd "$w" && $TAR -czf "$f" ./debian-binary ./data.tar.gz ./control.tar.gz )
  echo "==> $f"
}

# Единственный бинарник на архитектуру феда Entware (mipsel-3.4 — мягкая плавучка,
# как и у OpenWrt; ARMv7 на Keenetic тоже soft-float, поэтому GOARM=5 один на оба феда).
mk mipselsf mipsel-3.4   mipsle
mk mipssf   mips-3.4     mips
mk armv5sf  armv5-3.2    armv5
mk armv7sf  armv7-3.2    armv5
mk aarch64  aarch64-3.10 arm64

# те же бинарники отдельными файлами — для запуска без opkg
for n in mipsle mips armv5 arm64; do
  if [ -f "$BIN/usque-linux-$n" ]; then
    cp "$BIN/usque-linux-$n" "$OUT/usque_${VER}_linux_$n"
  fi
done

ls -l "$OUT"
