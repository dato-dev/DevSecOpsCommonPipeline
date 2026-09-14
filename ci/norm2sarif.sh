#!/bin/sh
# Нормализованный отчёт -> SARIF 2.1.0 для GitHub Code Scanning.
#
# Почему конвертер, а не нативный SARIF каждого инструмента: почти все умеют
# SARIF только отдельным форматом вывода, то есть вторым прогоном. Для trivy и
# checkov это удвоение самого долгого шага ради формата, а не ради находок.
# Исключение — semgrep: он пишет оба файла за один проход, и его SARIF богаче
# (метаданные правил, CWE, ссылки), поэтому у него в реестре sarif=native.
#
# GitHub придирчив к трём вещам, и на каждой SARIF молча не показывается:
#   * security-severity — строка с числом, по ней сортируется список находок;
#     без неё всё падает в "warning" и приоритет теряется;
#   * ruleIndex обязан указывать на существующий элемент rules;
#   * startLine >= 1. Ноль — ошибка валидации, а у находок без строки
#     (уязвимость пакета, алерт DAST) строки нет, поэтому region опускается.
set -u
tool=${1:?укажите инструмент}
norm="${SEC_REPORT_DIR:?}/$tool.norm.json"

jq --arg tool "$tool" '
	def score:
		if . == "critical" then "9.0"
		elif . == "high" then "7.0"
		elif . == "medium" then "5.0"
		elif . == "low" then "3.0"
		else "0.0" end;
	def level:
		if . == "critical" or . == "high" then "error"
		elif . == "medium" then "warning"
		else "note" end;

	. as $f
	| ([$f[] | .rule] | unique) as $ids
	| {
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0",
		runs: [{
			tool: { driver: {
				name: $tool,
				informationUri: "https://github.com/",
				rules: [ $ids[] as $id
					| ([$f[] | select(.rule == $id)] | first) as $one
					| {
						id: $id,
						name: $id,
						shortDescription: { text: ($one.title // $id) },
						helpUri: (if ($one.extra // "") | startswith("http") then $one.extra else null end),
						help: { text: ($one.extra // $one.title // $id) },
						defaultConfiguration: { level: ($one.severity | level) },
						properties: {
							tags: [$one.category // "security"],
							"security-severity": ($one.severity | score)
						}
					} | with_entries(select(.value != null))
				]
			}},
			results: [ $f[] | . as $r | {
				ruleId: .rule,
				ruleIndex: ($ids | index($r.rule)),
				level: (.severity | level),
				message: { text: (.title + (if (.extra // "") != "" then "  [" + .extra + "]" else "" end)) },
				locations: [{
					physicalLocation: ({
						artifactLocation: { uri: (if (.file // "") == "" then "." else .file end) }
					} + (if (.line // 0) > 0 then { region: { startLine: .line } } else {} end))
				}],
				properties: { severity: .severity, tool: .tool }
			}]
		}]
	}' "$norm"
