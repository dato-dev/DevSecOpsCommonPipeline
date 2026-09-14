# osv-scanner — уязвимости зависимостей по базе OSV. Разбирает манифесты и
# lock-файлы статически: ничего не ставит, не резолвит и в сборку проекта не
# лезет.
#
# Это и есть причина, по которой он здесь вместо pip-audit. pip-audit, чтобы
# составить список пакетов, поднимает venv и делает pip install --dry-run —
# и на репозитории со старыми пинами спотыкается ровно там, где нужнее всего:
# у cryptography==3.2 нет колеса под свежий Python, pip уходит собирать её из
# исходников и падает. Получается сканер, который не работает именно на тех
# проектах, ради которых его ставили. Режим --no-deps не спасает: venv он
# поднимает всё равно.
#
# pip-audit остался в реестре с default=0 — включается через
# SEC_DEPS_TOOLS="osv-scanner pip-audit", если нужен именно он.
#
# С trivy-fs пересекается намеренно: базы наполняются по-разному, и расхождение
# между ними — обычное дело, а не повод выключить один из двух.
tool_run() {
	bin_tool osv-scanner >/dev/null || { bad "osv-scanner не найден в PATH"; return 1; }
	# shellcheck disable=SC2086
	osv-scanner scan source --recursive --format json --output "$OUT_JSON" \
		$ARGS "$SEC_SRC"
	rc=$?
	case "$rc" in
	0 | 1) return 0 ;;  # 1 — «нашлись уязвимости», это не сбой
	# 128 — «не найдено ни одного манифеста». Файла при этом нет вовсе, и без
	# отдельной ветки шаг выглядел бы как падение сканера.
	128)
		echo '{"results":[]}' >"$OUT_JSON"
		# shellcheck disable=SC2034  # читается в ci/run.sh

		TOOL_NOTE="манифестов зависимостей не найдено"
		return 0
		;;
	*) return "$rc" ;;
	esac
}

tool_norm() {
	# Считаем по группам, а не по записям: одна и та же уязвимость приезжает
	# из OSV трижды — как PYSEC, GHSA и CVE. osv-scanner сам сводит алиасы в
	# groups, и на тестовом проекте это разница между 79 «находками» и 44
	# настоящими. Считать алиасы отдельно значит утроить числа в дашборде.
	#
	# max_severity — это балл CVSS строкой. Границы стандартные для CVSS v3.
	# Пусто бывает у записей PYSEC без оценки: там medium, потому что «оценки
	# нет» — это не «неважно», а уязвимость без порога не дойдёт никуда.
	jq --arg src "$SEC_SRC" '
		def band($s):
			if $s == "" or $s == null then "medium"
			else ($s | tonumber) as $n |
				if $n >= 9.0 then "critical"
				elif $n >= 7.0 then "high"
				elif $n >= 4.0 then "medium"
				elif $n > 0 then "low"
				else "medium" end
			end;
		[ .results[]? | (.source.path // "") as $path | .packages[]? | . as $p |
			(.groups // [])[] | {
				severity: band(.max_severity),
				rule: (.ids[0] // "OSV"),
				title: ($p.package.name + " " + $p.package.version + ": " +
					((.ids // []) | join(", ")) +
					(if (.max_severity // "") != "" then " (CVSS " + .max_severity + ")" else "" end)),
				file: ($path | sub("^" + $src + "/?"; "")),
				line: 0,
				extra: ("https://osv.dev/vulnerability/" + (.ids[0] // ""))
			}]' "$OUT_JSON"
}
