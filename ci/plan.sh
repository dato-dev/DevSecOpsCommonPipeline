#!/bin/sh
# Что именно будет запущено. Единственное место, где принимается это решение.
#
#   sh ci/plan.sh                 # человекочитаемый план
#   sh ci/plan.sh --github        # config=<json> и matrix=<json> для GITHUB_OUTPUT
#
# Порядок разрешения настройки: input вызова > переменная репозитория (vars) >
# автодетект > дефолт. Инпуты и vars приезжают целыми JSON-объектами в SEC_INPUTS
# и SEC_VARS — тогда добавление новой ручки не требует правки YAML в двух местах
# и в каждом подключённом репозитории.
#
# План печатается всегда, даже когда пуст. «Ничего не запустилось» обязано быть
# видно в логе строкой, а не отсутствием строк: молчаливо пустой прогон выглядит
# как зелёная сборка и живёт так месяцами.
set -u
SEC_LIB=${SEC_LIB:-$(dirname -- "$0")/lib.sh}
. "$SEC_LIB"

command -v jq >/dev/null 2>&1 || die "jq не найден в PATH"

mode=${1:-"--human"}

# ------------------------------------------------------- разрешение настроек

defaults='{
  "SEC_LANGS": "auto",
  "SEC_SAST": "1", "SEC_LINT": "1", "SEC_SECRETS": "1", "SEC_DEPS": "1",
  "SEC_IAC": "1", "SEC_CONTAINER": "1", "SEC_SBOM": "1", "SEC_DAST": "0",
  "SEC_SAST_TOOLS": "auto", "SEC_LINT_TOOLS": "auto", "SEC_SECRETS_TOOLS": "auto",
  "SEC_DEPS_TOOLS": "auto", "SEC_IAC_TOOLS": "auto", "SEC_CONTAINER_TOOLS": "auto",
  "SEC_SBOM_TOOLS": "auto",
  "SEC_DAST_TOOLS": "auto",
  "SEC_SKIP_TOOLS": "",
  "SEC_FAIL_ON": "high",
  "SEC_LINT_FAIL_ON": "none",
  "SEC_SARIF": "1", "SEC_PR_COMMENT": "1", "SEC_DD": "0",
  "SEC_DAST_TARGET": ""
}'

# vars берём только с префиксом SEC_: в репозитории живут и чужие переменные.
# inputs — пустые значения отбрасываем, иначе неуказанный input затёр бы vars.
vars_json=${SEC_VARS:-}
inputs_json=${SEC_INPUTS:-}
[ -n "$vars_json" ] || vars_json='{}'
[ -n "$inputs_json" ] || inputs_json='{}'

config=$(jq -cn \
	--argjson d "$defaults" \
	--argjson v "$vars_json" \
	--argjson i "$inputs_json" '
	def clean_vars: with_entries(select(.key | startswith("SEC_")))
		| with_entries(.value |= tostring);
	def clean_inputs: with_entries(select(.value != null and (.value | tostring) != ""))
		| with_entries(.key |= ("SEC_" + (. | ascii_upcase | gsub("-"; "_"))))
		# secrets — зарезервированное слово в workflow_call, входом его назвать
		# нельзя. Вход называется secrets_scan и здесь возвращается к общему
		# имени категории, чтобы SEC_SECRETS был один и тот же и из входа, и из
		# переменной репозитория.
		| with_entries(.key |= (if . == "SEC_SECRETS_SCAN" then "SEC_SECRETS" else . end))
		| with_entries(.value |= tostring);
	$d + ($v | clean_vars) + ($i | clean_inputs)
') || die "не разобрать SEC_VARS/SEC_INPUTS"

# Дальше настройки читаются как обычные переменные окружения — те же имена, что
# и при локальном запуске ci/run.sh. @sh экранирует значение целиком.
eval "$(printf '%s' "$config" | jq -r 'to_entries[] | .key + "=" + (.value | @sh)')"

# ------------------------------------------------------------------- языки

if [ "$SEC_LANGS" = "auto" ]; then
	langs=$(sh "$SEC_ROOT/ci/detect.sh")
	detected="автодетект"
else
	langs=$SEC_LANGS
	detected="задано SEC_LANGS"
fi
[ -n "$langs" ] || langs="none"

lang_match() { # список языков инструмента
	[ "$1" = "any" ] && return 0
	for l in $(printf '%s' "$1" | tr ',' ' '); do
		case " $langs " in *" $l "*) return 0 ;; esac
	done
	return 1
}

listed() { # инструмент список
	case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# --------------------------------------------------------------- отбор целей

selected=""
skipped=""
skip_reason() { skipped="$skipped$1\t$2\n"; }

for tool in $(reg_tools); do
	cat=$(reg_category "$tool")
	upper=$(printf '%s' "$cat" | tr 'a-z' 'A-Z')
	eval "on=\${SEC_${upper}:-1}"
	eval "pick=\${SEC_${upper}_TOOLS:-auto}"

	if listed "$tool" "$SEC_SKIP_TOOLS"; then
		skip_reason "$tool" "в SEC_SKIP_TOOLS"
		continue
	fi
	if [ "$on" != "1" ]; then
		skip_reason "$tool" "категория $cat выключена (SEC_$upper=$on)"
		continue
	fi
	if [ "$pick" != "auto" ] && ! listed "$tool" "$pick"; then
		skip_reason "$tool" "не назван в SEC_${upper}_TOOLS"
		continue
	fi
	if ! lang_match "$(reg_langs "$tool")"; then
		skip_reason "$tool" "нет языка $(reg_langs "$tool") (есть: $langs)"
		continue
	fi
	if ! needs_met "$(reg_needs "$tool")"; then
		skip_reason "$tool" "нет $(reg_needs "$tool") в дереве"
		continue
	fi
	if [ "$cat" = "dast" ] && [ -z "$SEC_DAST_TARGET" ]; then
		skip_reason "$tool" "DAST включён, но SEC_DAST_TARGET пуст"
		continue
	fi
	selected="$selected $tool"
done
selected=${selected# }

# Инструмент, названный в SEC_<CAT>_TOOLS, но отсутствующий в реестре — почти
# всегда опечатка. Молча проигнорировать её значит выключить проверку навсегда.
for cat in sast lint secrets deps iac container sbom dast; do
	upper=$(printf '%s' "$cat" | tr 'a-z' 'A-Z')
	eval "pick=\${SEC_${upper}_TOOLS:-auto}"
	[ "$pick" = "auto" ] && continue
	for t in $pick; do
		reg_category "$t" >/dev/null 2>&1 ||
			bad "SEC_${upper}_TOOLS: '$t' нет в реестре — опечатка?"
	done
done

# ------------------------------------------------------------------- вывод

if [ "$mode" = "--github" ]; then
	# Две матрицы, а не одна: DAST идёт в отдельном job на самом раннере.
	# Ему нужен docker (ZAP запускается контейнером) и сеть до проверяемого
	# приложения, а остальные инструменты работают внутри образа пайплайна,
	# где docker'а нет и не должно быть.
	emit() { # категория-фильтр(=|!=) dast
		for t in $selected; do
			c=$(reg_category "$t")
			case "$1" in
			only) [ "$c" = "dast" ] || continue ;;
			skip) [ "$c" = "dast" ] && continue ;;
			esac
			printf '{"tool":"%s","category":"%s"}\n' "$t" "$c"
		done | jq -cs '.'
	}
	printf 'config=%s\n' "$config"
	printf 'matrix=%s\n' "$(emit skip)"
	printf 'matrix_dast=%s\n' "$(emit only)"
	printf 'any=%s\n' "$([ -n "$selected" ] && echo 1 || echo 0)"
fi

{
	echo "Языки: $langs ($detected)"
	echo "План:  ${selected:-<пусто>}"
	[ -n "$skipped" ] && {
		echo "Пропущено:"
		printf '%b' "$skipped" | awk -F'\t' 'NF{printf "  %-14s %s\n", $1, $2}'
	}
	echo "Порог: SEC_FAIL_ON=$SEC_FAIL_ON (lint: $SEC_LINT_FAIL_ON)"
} >&2

[ -n "$selected" ] || note "не выбрано ни одного инструмента"
