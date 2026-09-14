#!/bin/sh
# Сводка в markdown: в Summary прогона и комментарием в PR.
#
#   sh ci/summary.sh > summary.md
#
# Комментарий один на PR и переписывается на каждом прогоне (ci/pr-comment.sh
# ищет маркер ниже). Двадцать комментариев от бота под одним PR читать никто
# не будет, а перезаписанный — прочитают, потому что он всегда последний.
set -u
SEC_LIB=${SEC_LIB:-$(dirname -- "$0")/lib.sh}
. "$SEC_LIB"

MARKER='<!-- devsecops-common-pipeline -->'
TOP=${SEC_SUMMARY_TOP:-20}

all=$(mktemp) || exit 1
trap 'rm -f "$all"' EXIT INT TERM
find "$SEC_REPORT_DIR" -name '*.norm.json' -type f 2>/dev/null |
	sort | xargs -r cat 2>/dev/null | jq -cs 'add // []' >"$all"

echo "$MARKER"
echo "## Проверки безопасности"
echo

if ! find "$SEC_REPORT_DIR" -name '*.norm.json' -type f 2>/dev/null | grep -q .; then
	echo "Ни один инструмент не отработал — смотрите логи job'ов."
	exit 0
fi

total=$(jq 'length' "$all")
if [ "$total" = "0" ]; then
	echo "Находок нет."
	exit 0
fi

echo "| Инструмент | Категория | Critical | High | Medium | Low | Info |"
echo "|---|---|--:|--:|--:|--:|--:|"
jq -r '
	def n($t; $s): [.[] | select(.tool == $t and .severity == $s)] | length;
	. as $f | [$f[].tool] | unique | .[] as $t |
	"| \($t) | \([$f[] | select(.tool == $t) | .category] | first) " +
	"| \($f | n($t; "critical")) | \($f | n($t; "high")) | \($f | n($t; "medium")) " +
	"| \($f | n($t; "low")) | \($f | n($t; "info")) |"' "$all"
echo

# Ссылки на строки кода собираются только в GitHub Actions: вне его нет ни
# GITHUB_REPOSITORY, ни коммита, и путь остаётся просто путём.
base=""
[ -n "${GITHUB_REPOSITORY:-}" ] && [ -n "${GITHUB_SHA:-}" ] &&
	base="${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY/blob/$GITHUB_SHA"

shown=$(jq -r --arg base "$base" --argjson top "$TOP" '
	def rank: if . == "critical" then 0 elif . == "high" then 1
		elif . == "medium" then 2 elif . == "low" then 3 else 4 end;
	def loc: if .file == "" or .file == null then "—"
		elif $base == "" then "`\(.file)`" + (if .line > 0 then ":\(.line)" else "" end)
		elif .line > 0 then "[\(.file):\(.line)](\($base)/\(.file)#L\(.line))"
		else "[\(.file)](\($base)/\(.file))" end;
	[.[] | select(.severity != "info" and .severity != "low")]
	| sort_by(.severity | rank) | .[0:$top] | .[]
	| "| \(.severity) | \(.tool) | `\(.rule)` | \(.title | gsub("\\|"; "\\\\|") | .[0:120]) | \(loc) |"' "$all")

if [ -n "$shown" ]; then
	echo "### Находки medium и выше"
	echo
	echo "| Важность | Инструмент | Правило | Что | Где |"
	echo "|---|---|---|---|---|"
	printf '%s\n' "$shown"
	hidden=$(jq --argjson top "$TOP" \
		'[.[] | select(.severity != "info" and .severity != "low")] | length
		 | if . > $top then . - $top else 0 end' "$all")
	[ "$hidden" != "0" ] && {
		echo
		echo "…и ещё $hidden. Полные отчёты — в артефактах прогона."
	}
	echo
fi

echo "<sub>Всего находок: $total. Отчёты всех инструментов приложены артефактом \`security-reports\`.</sub>"
