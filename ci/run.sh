#!/bin/sh
# Запуск одного инструмента.
#
#   sh ci/run.sh bandit                  # отчёты в ./reports/
#   SEC_SRC=/path/to/repo sh ci/run.sh semgrep
#
# На выходе три файла на инструмент:
#   reports/<tool>.json   нативный отчёт — его понимает парсер DefectDojo
#   reports/<tool>.norm.json  общая схема — по ней считаются пороги и сводка
#   reports/<tool>.sarif  для GitHub Code Scanning
#
# Код возврата — про то, отработал ли сканер, а не про то, нашёл ли он что-то.
# Смешать эти два смысла — самая частая ошибка в таких пайплайнах: «сборка
# красная» перестаёт отличать «5 уязвимостей» от «semgrep не стартовал», и
# через месяц второе принимают за первое и добавляют continue-on-error.
# Решение о падении принимает ci/gate.sh, отдельно и после всех прогонов.
set -u
SEC_LIB=${SEC_LIB:-$(dirname -- "$0")/lib.sh}
. "$SEC_LIB"

tool=${1:-}
[ -n "$tool" ] || die "укажите инструмент: $(reg_tools | tr '\n' ' ')"
reg_category "$tool" >/dev/null 2>&1 || die "$tool: нет в реестре ($REGISTRY)"
[ -f "$SEC_ROOT/ci/tools/$tool.sh" ] || die "$tool: нет ci/tools/$tool.sh"

# Общий список исключений. Его читают все инструменты — каждый своим флагом,
# но значение одно, иначе bandit проверяет .venv, а ruff нет, и числа находок
# в сводке необъяснимо расходятся.
SEC_EXCLUDE=${SEC_EXCLUDE:-".venv,venv,node_modules,.git,dist,build,.mypy_cache,.ruff_cache,.tox,site-packages"}
export SEC_EXCLUDE SEC_SRC SEC_ROOT

mkdir -p "$SEC_REPORT_DIR" || die "не создать $SEC_REPORT_DIR"
OUT_JSON="$SEC_REPORT_DIR/$tool.json"
OUT_NORM="$SEC_REPORT_DIR/$tool.norm.json"
OUT_SARIF="$SEC_REPORT_DIR/$tool.sarif"
OUT_LOG="$SEC_REPORT_DIR/$tool.log"
ARGS=$(tool_args "$tool")
export OUT_JSON OUT_NORM OUT_SARIF OUT_LOG ARGS
rm -f "$OUT_JSON" "$OUT_NORM" "$OUT_SARIF"

# shellcheck disable=SC1090
. "$SEC_ROOT/ci/tools/$tool.sh"

started=$(date +%s)
cd "$SEC_SRC" || die "нет каталога $SEC_SRC"

# Вывод инструмента идёт в файл, а не на экран: у semgrep это сотни строк
# прогресса, в которых теряется единственная важная строка про ошибку.
# При сбое лог показывается целиком ниже.
tool_run >"$OUT_LOG" 2>&1
rc=$?
took=$(( $(date +%s) - started ))

if [ ! -s "$OUT_JSON" ]; then
	bad "$tool: отчёт не создан (код $rc, ${took}с)"
	tail -n 15 "$OUT_LOG" 2>/dev/null | sed 's/^/      /' >&2
	exit 1
fi

if ! tool_norm >"$OUT_NORM" 2>"$OUT_LOG.norm"; then
	bad "$tool: отчёт создан, но не разобран — сменился формат вывода?"
	head -n 5 "$OUT_LOG.norm" | sed 's/^/      /' >&2
	# Нативный отчёт оставляем: в DefectDojo он уедет и без нормализации.
	echo '[]' >"$OUT_NORM"
	exit 1
fi

# Каждой находке проставляем инструмент: в сводке и в SARIF без этого не понять,
# кто её нашёл, а одну и ту же проблему находят двое.
tmp="$OUT_NORM.tmp"
jq --arg t "$tool" --arg c "$(reg_category "$tool")" \
	'[.[] | . + {tool: $t, category: $c}]' "$OUT_NORM" >"$tmp" && mv "$tmp" "$OUT_NORM"

case "$(reg_sarif "$tool")" in
none) : ;;                                          # инвентарь, а не находки
native) : ;;                                        # инструмент написал SARIF сам
*) sh "$SEC_ROOT/ci/norm2sarif.sh" "$tool" >"$OUT_SARIF" ;;
esac

# SARIF проверяется отдельно и жёстко. Его отсутствие не мешает ни порогу, ни
# сводке, ни DefectDojo — то есть шаг остаётся зелёным, а в Code Scanning
# просто ничего не приезжает. Один раз так и было: SEC_REPORT_DIR не
# экспортировался, norm2sarif падал, и семь инструментов подряд отчитались
# «ok», не создав ни одного файла.
if [ "${SEC_SARIF:-1}" = "1" ] && [ "$(reg_sarif "$tool")" != "none" ] &&
	[ ! -s "$OUT_SARIF" ]; then
	bad "$tool: SARIF не создан — в Code Scanning ничего не приедет"
	exit 1
fi

counts=$(jq -r '
	group_by(.severity) | map("\(.[0].severity): \(length)") | join(", ")
	| if . == "" then "чисто" else . end' "$OUT_NORM")
say "$tool — ${took}с — $counts"
rm -f "$OUT_LOG" "$OUT_LOG.norm"
