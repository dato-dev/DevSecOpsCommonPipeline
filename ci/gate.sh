#!/bin/sh
# Решение, падать ли сборке. Отдельный шаг после всех прогонов — намеренно.
#
#   sh ci/gate.sh                    # по всем reports/*.norm.json
#
# Порог задаётся на прогон (SEC_FAIL_ON) и переопределяется на категорию
# (SEC_SAST_FAIL_ON, SEC_LINT_FAIL_ON и т.д.). Значение — минимальная важность,
# которая валит сборку, либо none.
#
# Дефолт SEC_LINT_FAIL_ON=none стоит не из мягкости: линтер на чужом проекте
# даёт сотни срабатываний в первый же день. Красная сборка, которую никто не
# может починить за один заход, заканчивается одинаково — правило снимают
# целиком. Пусть лучше находки видно в сводке, а порог включат осознанно.
set -u
SEC_LIB=${SEC_LIB:-$(dirname -- "$0")/lib.sh}
. "$SEC_LIB"

# Таблица идёт в stdout, а say/bad — в stderr, и в логе CI они перемешиваются:
# «порог превышен» всплывает посреди таблицы. Сводим всё в один поток.
exec >&2

SEC_FAIL_ON=${SEC_FAIL_ON:-high}
IGNORE_FILE="$SEC_SRC/${SEC_IGNORE_FILE:-.security-ignore}"

# Подавление: строки вида `tool:rule` или `tool:*`, # — комментарий.
# Подавляется только влияние на порог. Находка остаётся в отчёте, в SARIF и в
# DefectDojo: список исключений — это «мы решили с этим жить», а не «этого нет».
ignored() { # tool rule
	[ -f "$IGNORE_FILE" ] || return 1
	awk -F: -v t="$1" -v r="$2" '
		/^[[:space:]]*#/ || NF < 2 { next }
		{ gsub(/[[:space:]]/, "") }
		$1 == t && ($2 == r || $2 == "*") { found = 1; exit }
		END { exit !found }
	' "$IGNORE_FILE"
}

all=$(mktemp) || exit 1
trap 'rm -f "$all"' EXIT INT TERM
find "$SEC_REPORT_DIR" -name '*.norm.json' -type f 2>/dev/null |
	sort | xargs -r cat 2>/dev/null | jq -cs 'add // []' >"$all"

total=$(jq 'length' "$all")
if [ "$total" = "0" ]; then
	# Ноль находок и ноль запущенных инструментов выглядят одинаково.
	# Различает их наличие самих файлов отчётов.
	if find "$SEC_REPORT_DIR" -name '*.norm.json' -type f 2>/dev/null | grep -q .; then
		say "находок нет"
	else
		bad "нет ни одного отчёта — ни один инструмент не отработал"
		exit 1
	fi
	exit 0
fi

echo
printf '%-14s %-10s %8s %8s %8s %8s %8s\n' ИНСТРУМЕНТ КАТЕГОРИЯ CRIT HIGH MED LOW INFO
fail=0
breaches=""

for tool in $(jq -r '[.[].tool] | unique[]' "$all"); do
	cat=$(reg_category "$tool" 2>/dev/null || echo "-")
	upper=$(printf '%s' "$cat" | tr 'a-z' 'A-Z')
	eval "threshold=\${SEC_${upper}_FAIL_ON:-\$SEC_FAIL_ON}"

	c=0 h=0 m=0 l=0 i=0 blocking=0
	for sev in critical high medium low info; do
		n=$(jq --arg t "$tool" --arg s "$sev" \
			'[.[] | select(.tool == $t and .severity == $s)] | length' "$all")
		# Подавление считается по конкретным правилам, а не по количеству.
		if [ "$n" != "0" ] && [ -f "$IGNORE_FILE" ]; then
			for rule in $(jq -r --arg t "$tool" --arg s "$sev" \
				'[.[] | select(.tool == $t and .severity == $s) | .rule] | unique[]' "$all"); do
				if ignored "$tool" "$rule"; then
					k=$(jq --arg t "$tool" --arg s "$sev" --arg r "$rule" \
						'[.[] | select(.tool == $t and .severity == $s and .rule == $r)] | length' "$all")
					n=$((n - k))
				fi
			done
		fi
		case $sev in
		critical) c=$n ;; high) h=$n ;; medium) m=$n ;; low) l=$n ;; info) i=$n ;;
		esac
		[ "$threshold" = "none" ] && continue
		[ "$(sev_rank "$sev")" -ge "$(sev_rank "$threshold")" ] &&
			blocking=$((blocking + n))
	done

	mark=""
	if [ "$blocking" -gt 0 ]; then
		mark=" <- порог $threshold: $blocking"
		fail=1
		breaches="$breaches $tool"
	fi
	printf '%-14s %-10s %8s %8s %8s %8s %8s%s\n' "$tool" "$cat" "$c" "$h" "$m" "$l" "$i" "$mark"
done

echo
if [ "$fail" = 0 ]; then
	say "порог не превышен (SEC_FAIL_ON=$SEC_FAIL_ON)"
else
	bad "порог превышен:${breaches}"
fi
exit "$fail"
