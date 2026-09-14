# Образ со всеми сканерами. Он же — граница воспроизводимости: состав находок
# определяется тегом образа, а не тем, что нашлось на раннере в этот вторник.
#
# Собирается в ghcr.io, версии приходят из versions.env (см. .github/workflows/image.yml).
# ZAP сюда намеренно не входит: это JVM плюс полсотни аддонов, около гигабайта
# ради шага, который по умолчанию выключен. DAST запускается отдельным
# контейнером в своём job.
FROM python:3.12-slim-bookworm

ARG TARGETARCH
ARG BANDIT_VERSION
ARG SEMGREP_VERSION
ARG RUFF_VERSION
ARG PIP_AUDIT_VERSION
ARG CHECKOV_VERSION
ARG OSV_SCANNER_VERSION
ARG TRIVY_VERSION
ARG GITLEAKS_VERSION
ARG HADOLINT_VERSION

# git нужен gitleaks (история) и pip-audit; jq — всему пайплайну; curl — заливке
# в DefectDojo. Больше ничего: каждый лишний пакет в образе сканера — это ещё
# один источник CVE в отчёте о самом пайплайне.
RUN apt-get update && apt-get install -y --no-install-recommends \
	git jq curl ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

# Инструменты Python ставятся в один общий venv на системном интерпретаторе.
# Здесь это безопасно (в образе больше ничего нет), а разнести их по отдельным
# окружениям значило бы четыре копии зависимостей ради изоляции, которой в
# одноразовом контейнере не от кого.
ENV VIRTUAL_ENV=/opt/scanners PATH=/opt/scanners/bin:$PATH
RUN python -m venv "$VIRTUAL_ENV" && pip install --no-cache-dir \
	"bandit==${BANDIT_VERSION}" \
	"semgrep==${SEMGREP_VERSION}" \
	"ruff==${RUFF_VERSION}" \
	"pip-audit==${PIP_AUDIT_VERSION}" \
	"checkov==${CHECKOV_VERSION}"

# Бинарные инструменты. Имена файлов в релизах у всех троих разные, поэтому
# TARGETARCH раскладывается для каждого отдельно.
# --retry: загрузки с CDN GitHub периодически отвечают 504, и сборка образа
# падает без всякого отношения к содержимому. Один такой 504 уже уронил сборку
# main ровно в том же коммите, где та же сборка по тегу прошла.
RUN set -eu; \
	curl() { command curl --retry 5 --retry-all-errors --retry-delay 3 "$@"; }; \
	case "$TARGETARCH" in \
		amd64) TRIVY_A=Linux-64bit; GL_A=linux_x64;   HL_A=Linux-x86_64 ;; \
		arm64) TRIVY_A=Linux-ARM64; GL_A=linux_arm64; HL_A=Linux-arm64  ;; \
		*) echo "неизвестная архитектура: $TARGETARCH" >&2; exit 1 ;; \
	esac; \
	curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_A}.tar.gz" \
		| tar -xz -C /usr/local/bin trivy; \
	curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GL_A}.tar.gz" \
		| tar -xz -C /usr/local/bin gitleaks; \
	curl -fsSL -o /usr/local/bin/hadolint \
		"https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-${HL_A}"; \
	curl -fsSL -o /usr/local/bin/osv-scanner \
		"https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH}"; \
	chmod +x /usr/local/bin/hadolint /usr/local/bin/osv-scanner

# Базу уязвимостей trivy в образ не кладём: это ещё под гигабайт, и она
# устаревает быстрее, чем пересобирается образ. Trivy скачивает её сам, а в
# GitHub Actions её кэширует шаг с actions/cache.
ENV TRIVY_CACHE_DIR=/tmp/trivy

# git отказывается работать с каталогом, чей владелец не совпадает с
# пользователем процесса, а в GitHub Actions это ровно наш случай: репозиторий
# принадлежит runner, а контейнер идёт от root. Без этой строки gitleaks видит
# «not a git repository» на настоящем репозитории.
RUN git config --global --add safe.directory '*'

COPY . /opt/pipeline
ENV SEC_ROOT=/opt/pipeline PATH=/opt/pipeline/ci:$PATH
WORKDIR /src

RUN bandit --version && semgrep --version && ruff --version \
	&& pip-audit --version && checkov --version >/dev/null \
	&& trivy --version && gitleaks version && hadolint --version \
	&& osv-scanner --version
