#!/bin/sh
# Заливка отчётов из reports/ в DefectDojo.
#
#   DD_URL=... DD_TOKEN=... sh ci/dd-push.sh          # всё, что есть в reports/
#   sh ci/dd-push.sh bandit semgrep                   # только эти
#
# Доступ берётся из ~/.dd.env (chmod 600), чтобы токен не оседал в history:
#   DD_URL=https://defectdojo.example
#   DD_TOKEN=...
#
# Что во что уезжает, решает реестр: колонка dd_scan_type. Прочерк означает,
# что парсера у DefectDojo для этого инструмента нет (ruff), и отчёт остаётся
# только в артефактах и в Code Scanning.
#
# Engagement — по категории (sast, deps, secrets, iac, dast). Это не косметика:
# close_old_findings закрывает в engagement всё, чего нет в новом отчёте, и
# один общий engagement означал бы, что заливка bandit закрывает находки trivy
# как «исчезнувшие». Раздельные engagement делают прогоны независимыми.
#
# Скрипт зовёт reimport-scan, а не import-scan. Разница видна не сразу: import
# создаёт новый Test на каждый запуск, и через месяц в engagement тридцать
# тестов с одними и теми же CVE, а «когда уязвимость появилась» и «когда
# закрылась» посчитать уже нельзя. reimport дописывает в тот же Test:
# исчезнувшее закрывает, вернувшееся переоткрывает.
set -u
SEC_LIB=${SEC_LIB:-$(dirname -- "$0")/lib.sh}
. "$SEC_LIB"

# Файл читается, только если токен не пришёл из окружения. Иначе на раннере CI
# победил бы случайно оставшийся ~/.dd.env, и заливка молча ушла бы не в тот
# DefectDojo — а выглядело бы это как успешный прогон.
if [ -z "${DD_TOKEN:-}" ] && [ -f "$HOME/.dd.env" ]; then
	set -a
	. "$HOME/.dd.env"
	set +a
fi

DD_URL=${DD_URL:-}
DD_TOKEN=${DD_TOKEN:-}
# По умолчанию имя продукта — имя репозитория, тип продукта — владелец. Тогда
# подключение пайплайна к новому репозиторию не требует ничего настраивать:
# auto_create_context заводит продукт сам, и он оказывается на своём месте.
DD_PRODUCT=${DD_PRODUCT:-$(basename "${GITHUB_REPOSITORY:-$SEC_SRC}")}
DD_PRODUCT_TYPE=${DD_PRODUCT_TYPE:-$(dirname "${GITHUB_REPOSITORY:-repos/x}")}
DD_SERVICE=${DD_SERVICE:-}
# Info у trivy — это в основном unfixed-пакеты базового образа. С ними продукт
# нечитаем, и настоящие находки тонут.
DD_MIN_SEVERITY=${DD_MIN_SEVERITY:-Low}
# Выключить проверку сертификата целиком. Годится как затычка; предпочтительнее
# DD_CA_CERT ниже.
DD_INSECURE=${DD_INSECURE:-0}
# PEM корневого сертификата вашей инфраструктуры. Правильный путь для
# самоподписанных: проверка остаётся, доверяем ровно своему CA. Кладётся в
# secrets.DD_CA_CERT целиком, вместе со строками BEGIN/END CERTIFICATE.
DD_CA_CERT=${DD_CA_CERT:-}
DD_CLOSE_OLD=${DD_CLOSE_OLD:-true}

fail=0

# Как проверять сертификат. Три исхода, и порядок между ними не случаен:
# заданный CA всегда сильнее, чем «выключить проверку».
# Строка про TLS печатается всегда. Иначе по логу не отличить заливку с
# настоящей проверкой сертификата от заливки с -k: обе выглядят как «ok, API и
# токен приняты». А это разные вещи — во втором случае токен уходит в
# соединение, подлинность которого никто не подтверждал, и заметить, что CA
# перестал подхватываться, будет нечем.
tls=""
if [ -n "$DD_CA_CERT" ]; then
	ca=$(mktemp) || exit 1
	printf '%s\n' "$DD_CA_CERT" >"$ca"
	chmod 600 "$ca"
	trap 'rm -f "$ca"' EXIT INT TERM
	tls="--cacert $ca"
	tls_note="проверка по своему CA (DD_CA_CERT)"
	[ "$DD_INSECURE" = "1" ] &&
		tls_note="$tls_note; DD_INSECURE=1 не применён — заданный CA сильнее"
elif [ "$DD_INSECURE" = "1" ]; then
	# -k снимает проверку целиком: токен уходит в соединение, подлинность
	# которого никто не подтверждает. Внутри лаборатории это осознанный
	# размен, снаружи — нет. Правильнее положить свой CA в DD_CA_CERT.
	tls="-k"
	tls_note="ПРОВЕРКА ВЫКЛЮЧЕНА (DD_INSECURE=1)"
else
	tls_note="проверка по системным корневым"
fi

echo "DefectDojo: ${DD_URL:-<не задан>}  продукт: $DD_PRODUCT"
echo "TLS: $tls_note"

command -v curl >/dev/null 2>&1 || { bad "curl не найден в PATH"; fail=1; }
[ -n "$DD_URL" ] || { bad "DD_URL пуст"; fail=1; }
[ -n "$DD_TOKEN" ] || { bad "DD_TOKEN пуст"; fail=1; }
[ "$fail" = 0 ] || { echo "Не готово к запуску."; exit 1; }

# Токен проверяем ДО заливок: узнавать про 401 после десяти неудачных POST —
# значит десять раз прочитать в логе непонятную ошибку вместо одной понятной.
probe_err=$(mktemp) || exit 1
# shellcheck disable=SC2086  # $tls — это «--cacert <файл>» или «-k»; слова нужны
probe=$(curl -sS $tls -o /dev/null -w '%{http_code}' \
	-H "Authorization: Token $DD_TOKEN" \
	"$DD_URL/api/v2/product_types/?limit=1" 2>"$probe_err")
case "$probe" in
200) say "API и токен приняты" ;;
401 | 403) bad "API: токен отвергнут (HTTP $probe)"; fail=1 ;;
# 000 — соединение не состоялось: адрес, сеть или сертификат.
000)
	bad "API не отвечает"
	sed 's/^/      /' "$probe_err" >&2
	# Самая частая причина в самоподписанной инфраструктуре, и по тексту curl
	# не очевидно, что с этим делать.
	grep -qi "certificate" "$probe_err" &&
		bad "  Сертификат не проверяется. Положите свой CA в secrets.DD_CA_CERT" &&
		bad "  либо выставьте переменную DD_INSECURE=1, чтобы не проверять вовсе."
	fail=1
	;;
*) bad "API: неожиданный ответ HTTP $probe"; fail=1 ;;
esac
rm -f "$probe_err"
[ "$fail" = 0 ] || exit 1

# ------------------------------------------------------------------- контекст

if git -C "$SEC_SRC" rev-parse --git-dir >/dev/null 2>&1; then
	commit=$(git -C "$SEC_SRC" rev-parse HEAD)
	branch=$(git -C "$SEC_SRC" rev-parse --abbrev-ref HEAD)
else
	commit=${GITHUB_SHA:-}
	branch=${GITHUB_REF_NAME:-}
fi
version=${SEC_VERSION:-${commit:-unknown}}
[ -n "$commit" ] && version=$(printf '%s' "$version" | cut -c1-12)

push() { # файл scan_type engagement
	report=$1
	scan_type=$2
	engagement=$3

	set -- \
		-F "scan_type=$scan_type" \
		-F "file=@$report" \
		-F "auto_create_context=true" \
		-F "product_type_name=$DD_PRODUCT_TYPE" \
		-F "product_name=$DD_PRODUCT" \
		-F "engagement_name=$engagement" \
		-F "close_old_findings=$DD_CLOSE_OLD" \
		-F "minimum_severity=$DD_MIN_SEVERITY" \
		-F "active=true" \
		-F "verified=false" \
		-F "version=$version" \
		-F "scan_date=$(date -u +%Y-%m-%d)"
	[ -n "$DD_SERVICE" ] && set -- "$@" -F "service=$DD_SERVICE"
	[ -n "$commit" ] && set -- "$@" -F "commit_hash=$commit"
	[ -n "$branch" ] && set -- "$@" -F "branch_tag=$branch"

	# shellcheck disable=SC2086  # см. выше
	out=$(curl -sS $tls -X POST "$DD_URL/api/v2/reimport-scan/" \
		-H "Authorization: Token $DD_TOKEN" \
		-w '\n%{http_code}' "$@" 2>&1)
	code=$(printf '%s' "$out" | tail -n 1)
	body=$(printf '%s' "$out" | sed '$d')

	if [ "$code" != "201" ] && [ "$code" != "200" ]; then
		bad "$scan_type: HTTP $code"
		# Тело печатается целиком не для красоты: 400 от DefectDojo почти
		# всегда значит «нет такого scan_type», и точное имя парсера видно
		# только здесь.
		printf '%s\n' "$body" | head -c 500 | sed 's/^/      /' >&2
		fail=1
		return 1
	fi

	# В разных версиях DD поле называется по-разному; берём то, что нашлось.
	test_id=$(printf '%s' "$body" | sed -n 's/.*"test"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)
	[ -n "$test_id" ] || test_id=$(printf '%s' "$body" | sed -n 's/.*"test_id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)
	if [ -n "$test_id" ]; then
		say "$scan_type -> $DD_URL/test/$test_id"
	else
		say "$scan_type (HTTP $code, id теста не разобран)"
	fi
}

# --------------------------------------------------------------------- заливка

tools=$*
if [ -z "$tools" ]; then
	tools=$(find "$SEC_REPORT_DIR" -maxdepth 1 -name '*.json' \
		! -name '*.norm.json' ! -name '*.sbom.json' -type f 2>/dev/null |
		sed 's|.*/||; s|\.json$||' | sort)
fi
[ -n "$tools" ] || { note "в $SEC_REPORT_DIR нет отчётов"; exit 0; }

for tool in $tools; do
	report="$SEC_REPORT_DIR/$tool.json"
	[ -s "$report" ] || { note "$tool: отчёта нет — пропуск"; continue; }

	scan_type=$(reg_dd_type "$tool" 2>/dev/null) || {
		note "$tool: нет в реестре — пропуск"
		continue
	}
	[ "$scan_type" = "-" ] && { note "$tool: парсера в DefectDojo нет — пропуск"; continue; }

	cat=$(reg_category "$tool")
	upper=$(printf '%s' "$cat" | tr 'a-z' 'A-Z')
	eval "engagement=\${DD_ENGAGEMENT_${upper}:-\$cat}"
	push "$report" "$scan_type" "$engagement" || true
done

echo
if [ "$fail" = 0 ]; then
	echo "Готово. Всё залито."
else
	echo "Готово с ошибками — смотрите строки СБОЙ выше."
fi
exit "$fail"
