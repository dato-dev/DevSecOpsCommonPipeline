#!/bin/sh
# Обновление версий в versions.env до последних выпущенных.
#
#   sh ci/bump.sh            # показать, что изменится
#   sh ci/bump.sh --write    # записать
#
# Отдельной командой, а не автоматикой в сборке образа: новая версия сканера
# меняет состав находок, и это должно приезжать коммитом, который видно в
# истории, — иначе завтрашний скачок в дашборде будет нечем объяснить.
set -u
SEC_LIB=${SEC_LIB:-$(dirname -- "$0")/lib.sh}
. "$SEC_LIB"

write=0
[ "${1:-}" = "--write" ] && write=1
command -v curl >/dev/null 2>&1 || die "curl не найден"
command -v jq >/dev/null 2>&1 || die "jq не найден"

pypi() { # пакет
	curl -fsSL "https://pypi.org/pypi/$1/json" | jq -r '.info.version'
}

gh_latest() { # owner/repo
	# Без токена лимит 60 запросов в час на IP. В CI подставьте GITHUB_TOKEN.
	auth=""
	[ -n "${GITHUB_TOKEN:-}" ] && auth="-H \"Authorization: Bearer $GITHUB_TOKEN\""
	# shellcheck disable=SC2086
	eval curl -fsSL $auth "https://api.github.com/repos/$1/releases/latest" |
		jq -r '.tag_name' | sed 's/^v//'
}

check() { # переменная новая-версия
	eval "old=\${$1:-}"
	new=$2
	if [ -z "$new" ] || [ "$new" = "null" ]; then
		bad "$1: не удалось узнать последнюю версию"
		return 1
	fi
	if [ "$old" = "$new" ]; then
		note "$1 = $old (актуальна)"
		return 0
	fi
	say "$1: $old -> $new"
	[ "$write" = "1" ] && sed -i.bak "s|^$1=.*|$1=$new|" "$SEC_ROOT/versions.env"
	return 0
}

check BANDIT_VERSION    "$(pypi bandit)"
check SEMGREP_VERSION   "$(pypi semgrep)"
check RUFF_VERSION      "$(pypi ruff)"
check PIP_AUDIT_VERSION "$(pypi pip-audit)"
check CHECKOV_VERSION   "$(pypi checkov)"
check OSV_SCANNER_VERSION "$(gh_latest google/osv-scanner)"
check TRIVY_VERSION     "$(gh_latest aquasecurity/trivy)"
check GITLEAKS_VERSION  "$(gh_latest gitleaks/gitleaks)"
check HADOLINT_VERSION  "$(gh_latest hadolint/hadolint)"

rm -f "$SEC_ROOT/versions.env.bak"
[ "$write" = "1" ] && say "versions.env обновлён — пересоберите образ"
[ "$write" = "1" ] || note "это был показ; запись — sh ci/bump.sh --write"
