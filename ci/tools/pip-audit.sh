# pip-audit — уязвимости зависимостей Python по базе PyPI Advisory/OSV.
# Частично пересекается с trivy-fs, и это осознанно: базы наполняются
# по-разному, и расхождение между ними — обычное дело, а не повод выключить
# один из двух.
#
# Работает по requirements*.txt. Проекты на pyproject/poetry/uv покрывает
# trivy-fs по lock-файлам: заставлять pip-audit собирать проект (`pip-audit .`)
# значит выполнять в CI код сборки из проверяемого репозитория — цена выше
# пользы.
tool_run() {
	reqs=$(find "$SEC_SRC" -maxdepth 2 -name 'requirements*.txt' \
		-not -path '*/.venv/*' -not -path '*/node_modules/*' 2>/dev/null | sort)
	if [ -z "$reqs" ]; then
		note "pip-audit: нет requirements*.txt — зависимости покрывает trivy-fs"
		echo '{"dependencies":[]}' >"$OUT_JSON"
		return 0
	fi
	cmd=$(py_tool pip-audit "pip-audit==$PIP_AUDIT_VERSION")
	[ -n "$cmd" ] || { bad "pip-audit: нужен uv (для uvx) или pip-audit в PATH"; return 1; }
	# shellcheck disable=SC2086
	set -- $cmd --format json --progress-spinner off
	for r in $reqs; do set -- "$@" -r "$r"; done
	# shellcheck disable=SC2086
	set -- "$@" $ARGS
	"$@" >"$OUT_JSON"
}

tool_norm() {
	# pip-audit не отдаёт severity: в его выводе есть идентификатор и версии
	# с исправлением, но не оценка. Ставим medium — не info, иначе уязвимая
	# зависимость не дойдёт ни до одного порога, и не high, иначе каждая
	# сборка красная. Настоящую оценку добавит DefectDojo из своих источников.
	jq '[.dependencies[]? | . as $d | (.vulns // [])[] | {
		severity: "medium",
		rule: .id,
		title: ($d.name + " " + $d.version + ": " + .id +
			(if (.fix_versions | length) > 0
			 then " (исправлено в " + (.fix_versions | join(", ")) + ")"
			 else " (исправления нет)" end)),
		file: "requirements",
		line: 0,
		extra: ((.aliases // []) | join(", "))
	}]' "$OUT_JSON"
}
