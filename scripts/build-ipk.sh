#!/bin/sh
# Сборка .ipk для OpenWrt. Использование: scripts/build-ipk.sh [версия]
# Результат: dist/ipk/usque_<версия>_<арх>_openwrt.ipk
# SKIP_BUILD=1 — не компилировать, взять готовые dist/bin/usque-linux-<арх>.
set -eu
cd "$(dirname "$0")/.."
VER="${1:-$(date -u +%Y.%m.%d)}"
VER="${VER#v}"
OUT="$PWD/dist/ipk"; BIN="$PWD/dist/bin"
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
  build amd64    amd64
  build arm64    arm64
  build armv7    arm   GOARM=7
  build armv5    arm   GOARM=5
  build mipsle   mipsle   GOMIPS=softfloat
  build mips     mips     GOMIPS=softfloat
  build mips64   mips64   GOMIPS64=softfloat
  build mips64le mips64le GOMIPS64=softfloat
fi

TAR="tar --owner=0 --group=0 --numeric-owner --format=gnu"

mk() { # арх
  arch="$1"; bin="$BIN/usque-linux-$arch"
  [ -f "$bin" ] || { echo "нет $bin — пропуск" >&2; return 0; }
  w="$T/$arch"; mkdir -p "$w/data" "$w/control"

  install -D -m 755 "$bin"                    "$w/data/usr/bin/usque"
  install -D -m 755 scripts/ipk/openwrt.init  "$w/data/etc/init.d/usque"
  install -D -m 644 scripts/ipk/openwrt.config "$w/data/etc/config/usque"
  mkdir -p "$w/data/etc/usque"

  cat > "$w/control/postinst" <<'EOS'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
mkdir -p /etc/usque
echo "usque установлен. Дальше:"
echo "  1) usque -c /etc/usque/config.json register"
echo "  2) uci set usque.main.enabled=1 && uci commit usque"
echo "  3) /etc/init.d/usque enable && /etc/init.d/usque start"
exit 0
EOS
  cat > "$w/control/prerm" <<'EOS'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/usque stop 2>/dev/null
/etc/init.d/usque disable 2>/dev/null
exit 0
EOS
  printf '/etc/config/usque\n' > "$w/control/conffiles"
  chmod 755 "$w/control/postinst" "$w/control/prerm"

  size=$(du -sk "$w/data" | cut -f1); size=$((size*1024))
  cat > "$w/control/control" <<EOS
Package: usque
Version: $VER
Source: usque
Section: net
Priority: optional
Maintainer: usque
Architecture: all
Installed-Size: $size
Description: Cloudflare WARP client over MASQUE (binary for $arch)
EOS

  ( cd "$w/control" && $TAR -czf ../control.tar.gz ./control ./postinst ./prerm ./conffiles )
  ( cd "$w/data"    && $TAR -czf ../data.tar.gz . )
  echo "2.0" > "$w/debian-binary"
  f="$OUT/usque_${VER}_${arch}_openwrt.ipk"
  ( cd "$w" && $TAR -czf "$f" ./debian-binary ./data.tar.gz ./control.tar.gz )
  echo "==> $f"
}

for a in amd64 arm64 armv7 armv5 mipsle mips mips64 mips64le; do
  mk "$a"
done
ls -l "$OUT"
