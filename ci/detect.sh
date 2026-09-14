#!/bin/sh
# Какие языки есть в проверяемом дереве. Печатает список через пробел.
#
#   sh ci/detect.sh            # python
#   SEC_SRC=/path sh ci/detect.sh
#
# Детект — только дефолт. SEC_LANGS его отменяет целиком: автоматика ошибается
# на монорепах и на репозиториях, где один package.json остался от прошлой
# жизни, и тогда пайплайн молча гоняет eslint по мёртвому каталогу.
set -u
. "${SEC_LIB:-$(dirname -- "$0")/lib.sh}"

# Маркеры намеренно узкие: файл сборки, а не «есть хоть один .py». Скрипт
# deploy.py в репозитории на Go не делает проект питоновским, а bandit по нему
# даст находки, которые никто не станет чинить.
has() { needs_met "$1"; }

langs=""
add() { case " $langs " in *" $1 "*) ;; *) langs="$langs $1" ;; esac; }

has pyproject.toml && add python
has requirements.txt && add python
has requirements-dev.txt && add python
has setup.py && add python
has Pipfile && add python
has package.json && add js
has go.mod && add go
has pom.xml && add java
has build.gradle && add java
has build.gradle.kts && add java
has Cargo.toml && add rust
has "*.tf" && add terraform
has Chart.yaml && add helm
has Dockerfile && add docker

printf '%s\n' "${langs# }"
