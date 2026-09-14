# pip-audit — уязвимости зависимостей Python по базе PyPI Advisory/OSV.
# Частично пересекается с trivy-fs, и это осознанно: базы наполняются
# по-разному, и расхождение между ними — обычное дело, а не повод выключить
# один из двух.
#
# Работает по requirements*.txt. Проекты на pyproject/poetry/uv покрывает
# trivy-fs по lock-файлам: заставлять pip-audit собирать проект (`pip-audit .`)
# значит выполнять в CI код сборки из проверяемого репозитория — цена выше
# пользы.
#
# У pip-audit два несовместимых режима, и ни один не работает везде:
#
#   по умолчанию   резолвит зависимости через `pip install --dry-run`, то есть
#                  видит и транзитивные пакеты. Падает на любом файле, который
#                  не резолвится, — а таких в жизни много: пины, конфликтующие
#                  между собой, платформозависимые пакеты, внутренние индексы.
#   --no-deps      берёт ровно то, что перечислено, ничего не ставит и в сеть
#                  за резолвом не ходит. Требует, чтобы ВСЕ строки были
#                  закреплены через ==, иначе отказывается работать.
#
# Поэтому режим выбирается по содержимому файла, а если выбранный не сработал —
# пробуется второй. Молча пропустить проверку нельзя: «pip-audit не смог» и
# «уязвимостей нет» не должны выглядеть одинаково.
tool_run() {
	cmd=$(py_tool pip-audit "pip-audit==$PIP_AUDIT_VERSION")
	[ -n "$cmd" ] || { bad "pip-audit: нужен uv (для uvx) или pip-audit в PATH"; return 1; }

	reqs=$(find "$SEC_SRC" -maxdepth 2 -name 'requirements*.txt' \
		-not -path '*/.venv/*' -not -path '*/node_modules/*' 2>/dev/null | sort)
	if [ -z "$reqs" ]; then
		note "pip-audit: нет requirements*.txt — зависимости покрывает trivy-fs"
		echo '{"dependencies":[]}' >"$OUT_JSON"
		# shellcheck disable=SC2034  # читается в ci/run.sh

		TOOL_NOTE="нет requirements*.txt"
		return 0
	fi

	# Все ли строки-требования закреплены через ==. Пропускаем комментарии,
	# пустые строки и флаги (-r, --index-url и прочие).
	pinned=1
	for r in $reqs; do
		if grep -vE '^[[:space:]]*(#|-|$)' "$r" | grep -qvE '=='; then
			pinned=0
			break
		fi
	done

	# Закреплённый файл — сначала --no-deps: он быстрее, не ходит в сеть за
	# резолвом и не зависит от того, совместимы ли пины между собой.
	if [ "$pinned" = "1" ]; then
		order="nodeps resolve"
	else
		order="resolve nodeps"
	fi

	attempt() { # режим: nodeps | resolve
		m=$1
		# shellcheck disable=SC2086
		set -- $cmd --format json --progress-spinner off
		for r in $reqs; do set -- "$@" -r "$r"; done
		if [ "$m" = "nodeps" ]; then set -- "$@" --no-deps; fi
		# shellcheck disable=SC2086
		set -- "$@" $ARGS
		"$@" >"$OUT_JSON" 2>>"$OUT_JSON.err"
	}

	for m in $order; do
		if attempt "$m"; then
			if [ "$m" = "nodeps" ]; then
				# shellcheck disable=SC2034  # читается в ci/run.sh

				TOOL_NOTE="--no-deps (транзитивные зависимости смотрит trivy-fs)"
			else
				# shellcheck disable=SC2034  # читается в ci/run.sh

				TOOL_NOTE="с резолвом зависимостей"
			fi
			rm -f "$OUT_JSON.err"
			return 0
		fi
		note "pip-audit: режим $m не отработал, пробую второй"
	done

	bad "pip-audit: не отработал ни с резолвом зависимостей, ни с --no-deps."
	bad "  requirements*.txt не резолвится и закреплён при этом не весь."
	bad "  Лечится приведением файла в порядок, флагами в SEC_PIP_AUDIT_ARGS"
	bad "  или SEC_SKIP_TOOLS=pip-audit — зависимости и так смотрит trivy-fs."
	tail -n 5 "$OUT_JSON.err" 2>/dev/null | sed 's/^/      /' >&2
	rm -f "$OUT_JSON" "$OUT_JSON.err"
	return 1
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
