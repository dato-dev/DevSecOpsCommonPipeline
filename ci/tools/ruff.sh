# ruff — линтер Python. Здесь он не про стиль: включён набор S (flake8-bandit)
# и правила, которые ловят настоящие ошибки, — mutable default, except: pass,
# сравнение через is с литералом. Стилевые придирки в общем пайплайне не нужны,
# у каждого проекта свой pyproject, и ruff его читает.
#
# Если в проекте есть [tool.ruff] в pyproject.toml, он побеждает: SEC_RUFF_SELECT
# применяется только когда конфига нет, иначе пайплайн переспорил бы проект.
RUFF_SELECT=${SEC_RUFF_SELECT:-"E9,F,S,B,A,DTZ,T20"}

tool_run() {
	cmd=$(py_tool ruff "ruff==$RUFF_VERSION")
	[ -n "$cmd" ] || { bad "ruff: нужен uv (для uvx) или ruff в PATH"; return 1; }
	# shellcheck disable=SC2086
	set -- $cmd check --quiet --output-format json --no-cache
	# Проверяется именно секция [tool.ruff], а не наличие pyproject.toml:
	# pyproject есть почти в каждом проекте, и по его наличию SEC_RUFF_SELECT
	# не применился бы никогда — ruff молча гонял бы свой минимальный набор
	# по умолчанию (E4,E7,E9,F), в котором нет ни одного правила про
	# безопасность, и шаг был бы всегда зелёным.
	has_config=0
	[ -f "$SEC_SRC/ruff.toml" ] && has_config=1
	[ -f "$SEC_SRC/.ruff.toml" ] && has_config=1
	grep -q '^\[tool\.ruff' "$SEC_SRC/pyproject.toml" 2>/dev/null && has_config=1
	[ "$has_config" = "1" ] || set -- "$@" --select "$RUFF_SELECT"
	# shellcheck disable=SC2086
	set -- "$@" $ARGS "${SEC_PYTHON_PATHS:-.}"
	# ruff печатает отчёт в stdout, файла он не пишет.
	"$@" >"$OUT_JSON"
}

tool_norm() {
	# У ruff нет severity: линтер сообщает о нарушении правила, а не о риске.
	# Правила S* — это перенесённый bandit, они про безопасность; остальное
	# ниже, чтобы порог сборки не срабатывал на T201 (забытый print).
	jq '[.[] | {
		severity: (if (.code // "") | startswith("S") then "medium" else "low" end),
		rule: (.code // "unknown"),
		title: .message,
		file: (.filename | sub("^\\./"; "")),
		line: .location.row,
		extra: (.url // "")
	}]' "$OUT_JSON"
}
