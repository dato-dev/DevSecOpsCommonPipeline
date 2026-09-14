# bandit — SAST для Python. Разбирает код модулем ast, поэтому важен
# интерпретатор: под старым Python файл с новым синтаксисом не парсится и
# уезжает в errors, то есть остаётся молча непроверенным. В образе он один.
BANDIT_PATHS=${SEC_PYTHON_PATHS:-.}
BANDIT_EXCLUDE=${SEC_BANDIT_EXCLUDE:-$SEC_EXCLUDE}

tool_run() {
	# --exit-zero: код возврата 1 у bandit значит «нашлись проблемы», и без
	# этого флага находки неотличимы от падения самого сканера.
	# shellcheck disable=SC2086
	cmd=$(py_tool bandit "bandit==$BANDIT_VERSION")
	[ -n "$cmd" ] || { bad "bandit: нужен uv (для uvx) или bandit в PATH"; return 1; }
	# shellcheck disable=SC2086
	$cmd -r $BANDIT_PATHS -f json -o "$OUT_JSON" --exit-zero \
		--exclude "$BANDIT_EXCLUDE" $ARGS
}

tool_norm() {
	jq '[.results[] | {
		severity: (.issue_severity | ascii_downcase),
		rule: .test_id,
		title: .issue_text,
		file: (.filename | sub("^\\./"; "")),
		line: .line_number,
		extra: ("confidence: " + (.issue_confidence // "" | ascii_downcase))
	}]' "$OUT_JSON"
}
