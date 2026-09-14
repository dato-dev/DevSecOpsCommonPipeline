# checkov — мисконфиги инфраструктуры: terraform, k8s, helm, docker-compose,
# сам GitHub Actions. Пересекается с trivy misconfig, но заметно шире по
# фреймворкам и по числу правил.
tool_run() {
	# --compact и --quiet: без них checkov печатает в stdout всю таблицу,
	# а нам нужен только файл.
	# shellcheck disable=SC2086
	cmd=$(py_tool checkov "checkov==$CHECKOV_VERSION")
	[ -n "$cmd" ] || { bad "checkov: нужен uv (для uvx) или checkov в PATH"; return 1; }
	# shellcheck disable=SC2086
	$cmd --directory "$SEC_SRC" --output json --output-file-path "$(dirname "$OUT_JSON")" \
		--quiet --compact --soft-fail \
		--skip-path "$(printf '%s' "$SEC_EXCLUDE" | tr ',' '|')" $ARGS >/dev/null 2>&1
	# checkov кладёт файл под своим именем; приводим к нашему.
	[ -f "$(dirname "$OUT_JSON")/results_json.json" ] &&
		mv "$(dirname "$OUT_JSON")/results_json.json" "$OUT_JSON"
	[ -f "$OUT_JSON" ]
}

tool_norm() {
	# Форма вывода зависит от числа найденных фреймворков: один — объект,
	# несколько — массив объектов. Приводим к массиву в обоих случаях.
	jq '[ (if type == "array" then .[] else . end)
		| (.results.failed_checks // [])[] | {
			severity: ((.severity // "medium") | ascii_downcase),
			rule: .check_id,
			title: (.check_name // .check_id),
			file: (.file_path | sub("^/"; "")),
			line: ((.file_line_range // [0])[0]),
			extra: (.guideline // "")
		}]' "$OUT_JSON"
}
