# semgrep — SAST по правилам. Единственный инструмент, у которого SARIF берётся
# нативным: он даёт метаданные правил, ссылки на CWE/OWASP и security-severity,
# по которой GitHub сортирует находки. Оба формата пишутся за один прогон
# (--json-output и --sarif-output), второй запуск стоил бы столько же, сколько
# первый — semgrep самый долгий шаг пайплайна.
#
# Реестровые наборы p/* тянутся с semgrep.dev по сети. Если это неприемлемо,
# укажите в SEC_SEMGREP_CONFIG путь к локальному каталогу с правилами.
SEMGREP_CONFIG=${SEC_SEMGREP_CONFIG:-"p/default p/security-audit p/secrets p/trailofbits p/command-injection p/sql-injection p/insecure-transport"}
# Документация исключена: правила вроде curl-unencrypted-url срабатывают на
# примерах команд в markdown. Это находки про текст, а не про код.
SEMGREP_EXCLUDE=${SEC_SEMGREP_EXCLUDE:-"*.md"}

tool_run() {
	# --metrics=off: с реестровыми правилами semgrep иначе шлёт телеметрию.
	cmd=$(py_tool semgrep "semgrep==$SEMGREP_VERSION")
	[ -n "$cmd" ] || { bad "semgrep: нужен uv (для uvx) или semgrep в PATH"; return 1; }
	# shellcheck disable=SC2086
	set -- $cmd scan --quiet --metrics=off --disable-version-check \
		--json-output "$OUT_JSON" --sarif-output "$OUT_SARIF" \
		--timeout "${SEC_SEMGREP_TIMEOUT:-120}"
	# set -f на время разбора списков. Без него shell раскроет `*.md` по текущему
	# каталогу и подставит README.md вместо всех markdown: исключатся три файла в
	# корне, а находки из docs/ продолжат приходить. Ошибка тихая — команда
	# отрабатывает успешно.
	set -f
	for c in $SEMGREP_CONFIG; do set -- "$@" --config "$c"; done
	for e in $SEMGREP_EXCLUDE; do set -- "$@" --exclude "$e"; done
	for e in $(printf '%s' "$SEC_EXCLUDE" | tr ',' ' '); do set -- "$@" --exclude "$e"; done
	set +f
	# shellcheck disable=SC2086
	set -- "$@" $ARGS "${SEC_PYTHON_PATHS:-.}"
	"$@"
}

tool_norm() {
	jq '[.results[] | {
		severity: (
			(.extra.metadata.impact // "" | ascii_downcase) as $impact |
			if .extra.severity == "ERROR" and $impact == "high" then "critical"
			elif .extra.severity == "ERROR" then "high"
			elif .extra.severity == "WARNING" then "medium"
			else "low" end),
		rule: .check_id,
		title: (.extra.message | split("\n")[0]),
		file: (.path | sub("^\\./"; "")),
		line: .start.line,
		extra: ((.extra.metadata.cwe // []) | if type == "array" then join(", ") else . end)
	}]' "$OUT_JSON"
}
