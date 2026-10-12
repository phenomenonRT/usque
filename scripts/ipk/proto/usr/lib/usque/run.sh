#!/bin/sh
# Обёртка запуска usque для netifd: пишет журнал и PID, затем заменяет себя usque.
# Использование: run.sh <интерфейс> <команда> [аргументы...]
# Журнал: /var/run/usque/<интерфейс>.log (в RAM; виден в LuCI на странице интерфейса).

IF="$1"
shift
[ -n "$IF" ] && [ $# -gt 0 ] || exit 1

D=/var/run/usque
LOG="$D/$IF.log"
mkdir -p "$D"

# журнал не должен расти бесконечно (это память роутера)
if [ -f "$LOG" ] && [ "$(wc -l < "$LOG")" -gt 400 ]; then
	tail -n 200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

echo "$$" > "$D/$IF.pid"
echo "--- $(date '+%F %T') запуск: $*" >> "$LOG"

exec "$@" >> "$LOG" 2>&1
