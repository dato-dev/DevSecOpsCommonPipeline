# hadolint — линтер Dockerfile. В категории container, а не lint: половина его
# правил про безопасность образа (root-пользователь, apt без --no-install-recommends,
# curl | sh в RUN, отсутствие закреплённых версий пакетов).
tool_run() {
	bin_tool hadolint >/dev/null || { bad "hadolint не найден в PATH"; return 1; }
	files=$(find "$SEC_SRC" -maxdepth 3 -name 'Dockerfile*' \
		-not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | sort)
	[ -n "$files" ] || { echo '[]' >"$OUT_JSON"; return 0; }
	# shellcheck disable=SC2086
	hadolint --format json --no-fail $ARGS $files >"$OUT_JSON"
}

tool_norm() {
	jq --arg src "$SEC_SRC" '[.[]? | {
		severity: (
			if .level == "error" then "medium"
			elif .level == "warning" then "low"
			else "info" end),
		rule: .code,
		title: .message,
		file: (.file | sub("^" + $src + "/?"; "")),
		line: (.line // 0),
		extra: (.level // "")
	}]' "$OUT_JSON"
}
