#!/bin/sh
# Публикация сводки комментарием в PR. Один комментарий на PR: ищем свой по
# маркеру и переписываем, а не добавляем новый.
#
#   GITHUB_TOKEN=... sh ci/pr-comment.sh summary.md
#
# Нужен permissions: pull-requests: write. Без него API отвечает 403, и это не
# повод валить прогон — комментарий удобство, а не проверка.
set -u
SEC_LIB=${SEC_LIB:-$(dirname -- "$0")/lib.sh}
. "$SEC_LIB"

body_file=${1:?укажите файл со сводкой}
MARKER='<!-- devsecops-common-pipeline -->'
: "${GITHUB_TOKEN:?нет GITHUB_TOKEN}"
: "${GITHUB_REPOSITORY:?не GitHub Actions}"

pr=${PR_NUMBER:-}
[ -n "$pr" ] || pr=$(jq -r '.pull_request.number // .number // empty' \
	"${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null)
[ -n "$pr" ] || { note "не PR — комментарий не нужен"; exit 0; }

api="${GITHUB_API_URL:-https://api.github.com}/repos/$GITHUB_REPOSITORY"
auth="Authorization: Bearer $GITHUB_TOKEN"

existing=$(curl -sS -H "$auth" "$api/issues/$pr/comments?per_page=100" |
	jq -r --arg m "$MARKER" '[.[] | select(.body | contains($m))] | last | .id // empty')

payload=$(jq -Rs '{body: .}' <"$body_file")
if [ -n "$existing" ]; then
	url="$api/issues/comments/$existing"; method=PATCH
else
	url="$api/issues/$pr/comments"; method=POST
fi

code=$(curl -sS -o /dev/null -w '%{http_code}' -X "$method" "$url" \
	-H "$auth" -H "Content-Type: application/json" -d "$payload")
case "$code" in
200 | 201) say "комментарий в PR #$pr обновлён" ;;
403) note "нет прав на комментарий (403) — нужен permissions: pull-requests: write" ;;
*) bad "комментарий в PR: HTTP $code" ;;
esac
exit 0
