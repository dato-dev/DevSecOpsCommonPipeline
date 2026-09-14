# Фикстура для самопроверки пайплайна. Каждая строка ниже обязана быть найдена
# хотя бы одним инструментом; если самопроверка позеленела на этом файле,
# сломался пайплайн, а не код.
import os
import subprocess

import yaml

PASSWORD = "hunter2-not-a-real-secret"  # bandit B105


def run(cmd):
    return subprocess.call(cmd, shell=True)  # bandit B602, semgrep


def load(text):
    return yaml.load(text)  # bandit B506


def query(conn, user):
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % user)  # sql-injection


def tmp():
    return open("/tmp/state", "w")  # bandit B108


def swallow():
    try:
        os.unlink("/nope")
    except Exception:  # ruff/bandit B110
        pass
