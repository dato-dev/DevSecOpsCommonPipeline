# OWASP ZAP — DAST по запущенному приложению. Единственный инструмент, которому
# нужен не исходный код, а работающий сервис: SEC_DAST_TARGET.
#
# Запускается docker'ом, а не из образа пайплайна: ZAP — это JVM плюс полсотни
# аддонов, класть его в общий образ значит утроить его размер ради шага, который
# по умолчанию выключен. Поэтому DAST в отдельном job на самом раннере.
#
# Режимы (SEC_ZAP_MODE):
#   baseline — пассивный, только то, что видно из обычных ответов. Минуты.
#   full     — активный: ZAP шлёт атакующие запросы, меняет и создаёт данные.
#              Никогда не по продакшену и не по чужому стенду. Десятки минут.
#   api      — по OpenAPI/GraphQL-описанию из SEC_ZAP_SPEC.
ZAP_MODE=${SEC_ZAP_MODE:-baseline}
ZAP_IMAGE=${SEC_ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}

tool_run() {
	bin_tool docker >/dev/null || { bad "docker не найден — ZAP запускается контейнером"; return 1; }
	[ -n "${SEC_DAST_TARGET:-}" ] || { bad "SEC_DAST_TARGET пуст"; return 1; }
	dir=$(dirname "$OUT_JSON")
	name=$(basename "$OUT_JSON")

	case "$ZAP_MODE" in
	baseline) script=zap-baseline.py ;;
	full)     script=zap-full-scan.py ;;
	api)      script=zap-api-scan.py ;;
	*) bad "SEC_ZAP_MODE: ожидается baseline|full|api, а не '$ZAP_MODE'"; return 1 ;;
	esac

	set -- docker run --rm --network "${SEC_DAST_NETWORK:-host}" \
		-v "$dir:/zap/wrk:rw" -u "$(id -u)" "$ZAP_IMAGE" "$script" \
		-t "$SEC_DAST_TARGET" -J "$name" -I
	[ "$ZAP_MODE" = "api" ] && set -- "$@" -f "${SEC_ZAP_FORMAT:-openapi}"
	# Правила, которые нужно приглушить, живут в файле проекта, а не в
	# переменной: список исключений всегда обрастает комментариями «почему».
	[ -f "$SEC_SRC/.zap/rules.tsv" ] && set -- "$@" -c .zap/rules.tsv
	# shellcheck disable=SC2086
	set -- "$@" $ARGS
	# -I: не падать на предупреждениях. Судим по файлу отчёта, как везде.
	"$@"
}

tool_norm() {
	jq '[.site[]? | .alerts[]? | {
		severity: (
			if .riskcode == "3" then "high"
			elif .riskcode == "2" then "medium"
			elif .riskcode == "1" then "low"
			else "info" end),
		rule: (.pluginid // .alertRef // "zap"),
		title: (.alert // .name),
		file: ((.instances // [])[0].uri // ""),
		line: 0,
		extra: ((.instances // []) | length | tostring + " экземпляр(ов)")
	}]' "$OUT_JSON"
}
