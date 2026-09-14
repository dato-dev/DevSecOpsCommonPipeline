# trivy fs — зависимости по lock-файлам, секреты и мисконфиги в одном проходе.
# Три сканера вместе, потому что дерево обходится один раз, а оно самое дорогое.
tool_run() {
	bin_tool trivy >/dev/null || { bad "trivy не найден в PATH"; return 1; }
	# shellcheck disable=SC2086
	trivy fs --quiet --format json --output "$OUT_JSON" \
		--scanners "${SEC_TRIVY_SCANNERS:-vuln,secret,misconfig}" \
		--skip-dirs "$(printf '%s' "$SEC_EXCLUDE" | tr ',' ' ' | tr ' ' ',')" \
		$ARGS "$SEC_SRC"
}

tool_norm() {
	# У trivy три вида находок с разной формой. Severity общий (UNKNOWN..CRITICAL),
	# так что различаются они только тем, что писать в rule и title.
	jq --arg src "$SEC_SRC" '
		def rel: sub("^" + ($src | gsub("[.*+?^$()|\\[\\]{}\\\\]"; "\\\\\\(.)")) + "/?"; "") | sub("^\\./"; "");
		[ .Results[]? |
			(.Target // "") as $t |
			((.Vulnerabilities // [])[] | {
				severity: (.Severity | ascii_downcase),
				rule: .VulnerabilityID,
				title: (.PkgName + " " + (.InstalledVersion // "?") + ": " + .VulnerabilityID +
					(if .FixedVersion then " (исправлено в " + .FixedVersion + ")" else " (исправления нет)" end)),
				file: ($t | rel), line: 0,
				extra: (.PrimaryURL // "")
			}),
			((.Misconfigurations // [])[] | {
				severity: (.Severity | ascii_downcase),
				rule: .ID,
				title: .Title,
				file: ($t | rel), line: (.CauseMetadata.StartLine // 0),
				extra: (.PrimaryURL // "")
			}),
			((.Secrets // [])[] | {
				severity: (.Severity | ascii_downcase),
				rule: .RuleID,
				title: .Title,
				file: ($t | rel), line: (.StartLine // 0),
				extra: ""
			})
		]' "$OUT_JSON"
}
