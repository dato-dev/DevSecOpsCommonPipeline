#!/bin/sh
# Общее для всех скриптов пайплайна: логи, чтение реестра, шкала severity.
# Подключается через `. "$SEC_ROOT/ci/lib.sh"`, сам ничего не делает.

# Корень пайплайна (репозиторий devsecops-common-pipeline), а не проверяемого
# проекта. Их разделение важно: SEC_SRC — что сканируем, SEC_ROOT — чем.
SEC_ROOT=${SEC_ROOT:-$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)}
SEC_SRC=${SEC_SRC:-$PWD}
SEC_REPORT_DIR=${SEC_REPORT_DIR:-$SEC_SRC/reports}
REGISTRY=${REGISTRY:-$SEC_ROOT/registry.tsv}
# Экспортируются все четыре: скрипты зовут друг друга (run.sh -> norm2sarif.sh),
# и не-экспортированный SEC_REPORT_DIR оборачивается тем, что дочерний скрипт
# падает, а родительский этого не замечает и рапортует «ok».
export SEC_ROOT SEC_SRC SEC_REPORT_DIR REGISTRY

say()  { printf '  ok    %s\n' "$1" >&2; }
note() { printf '  --    %s\n' "$1" >&2; }
bad()  { printf '  СБОЙ  %s\n' "$1" >&2; }
die()  { bad "$1"; exit 1; }

# ------------------------------------------------------------------- реестр

# Поле строки реестра по имени инструмента. Колонки: 1 tool, 2 category,
# 3 langs, 4 needs, 5 dd_scan_type, 6 sarif.
reg() { # инструмент номер-колонки
	awk -F'\t' -v t="$1" -v c="$2" '
		/^#/ || NF < 7 { next }
		$1 == t { print $c; found = 1; exit }
		END { if (!found) exit 1 }
	' "$REGISTRY"
}

reg_tools() { awk -F'\t' '!/^#/ && NF >= 7 { print $1 }' "$REGISTRY"; }

reg_category()  { reg "$1" 2; }
reg_langs()     { reg "$1" 3; }
reg_needs()     { reg "$1" 4; }
reg_dd_type()   { reg "$1" 5; }
reg_sarif()     { reg "$1" 6; }
reg_default()   { reg "$1" 7; }

# ----------------------------------------------------------------- severity

# Единая шкала. Каждый tool_norm приводит свои названия к ней: без этого
# «high» у bandit и «HIGH» у trivy и «error» у ruff несравнимы, а порог
# падения сборки должен быть один на весь прогон.
sev_rank() { # severity -> число; больше = хуже
	case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
	critical) echo 5 ;;
	high)     echo 4 ;;
	medium)   echo 3 ;;
	low)      echo 2 ;;
	info | informational | note | unknown | "") echo 1 ;;
	*) echo 1 ;;
	esac
}

# Значение SEC_<TOOL>_ARGS — дополнительные флаги для конкретного инструмента.
# Дефис в имени инструмента (trivy-fs, pip-audit) в имени переменной становится
# подчёркиванием: SEC_TRIVY_FS_ARGS, SEC_PIP_AUDIT_ARGS.
tool_args() { # инструмент
	var="SEC_$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')_ARGS"
	eval "printf '%s' \"\${$var:-}\""
}

# Есть ли в проверяемом дереве то, без чего инструмент бессмыслен.
# Глоб ищется на два уровня вглубь: Dockerfile в корне или в services/*/.
needs_met() { # шаблон
	[ "$1" = "-" ] && return 0
	set -f
	# shellcheck disable=SC2086
	set -- "$SEC_SRC"/$1 "$SEC_SRC"/*/$1 "$SEC_SRC"/*/*/$1
	set +f
	for p in "$@"; do [ -e "$p" ] && return 0; done
	return 1
}

# ------------------------------------------------------------- запуск бинарей

# Версии из одного файла — их же использует Dockerfile.
[ -f "$SEC_ROOT/versions.env" ] && . "$SEC_ROOT/versions.env"

# Python-инструмент: команда запуска или пусто, если запустить нечем.
#
# uvx впереди PATH намеренно. Инструмент с PATH — это чужая версия на чужом
# интерпретаторе: на раннере им оказывается системный python, под которым
# semgrep не стартует, а bandit разбирает код модулем ast этого же
# интерпретатора и на файле с новым синтаксисом молча уходит в errors, то есть
# оставляет его непроверенным. uvx даёт закреплённую версию на закреплённом
# Python, то есть один и тот же состав находок локально и в CI.
#
# В образе пайплайна uvx нет, а инструмент стоит нужной версии на нужном
# Python — там срабатывает вторая ветка, и это тот же самый результат.
py_tool() { # бинарь спецификация-пакета
	if command -v uvx >/dev/null 2>&1; then
		printf 'uvx --quiet --python %s --from %s %s' "${SEC_PYTHON:-3.12}" "$2" "$1"
	elif command -v "$1" >/dev/null 2>&1; then
		printf '%s' "$1"
	fi
}

# Бинарный инструмент: он либо есть, либо шага не будет. Ставить его на лету
# из сети в момент проверки — значит поставить проверку в зависимость от
# доступности чужого CDN.
bin_tool() { # бинарь
	command -v "$1" >/dev/null 2>&1 && printf '%s' "$1"
}
