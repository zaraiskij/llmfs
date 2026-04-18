#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════╗
║       LLM FILTER SCANNER v0.9.1  —  Анализатор AI-сервисов          ║
║  Статика • Прокси-инспектор • Мониторинг • Профили • Библиотека     ║
╚══════════════════════════════════════════════════════════════════════╝
Запуск:  python3 llmfs091.py
Данные:  ~/Documents/llmfs/
"""

import os, re, sys, json, time, struct, subprocess, ipaddress, threading, http.client
import glob as _glob
from pathlib import Path
from datetime import datetime

VERSION = "0.9.1"
SERVICES_UPDATE_URL = ""  # URL для обновления services.json с GitHub (заполнить после создания репо)

# ── --version / --help ────────────────────────────────────────────────
if len(sys.argv) > 1:
    arg = sys.argv[1].lower()
    if arg in ('--version', '-v', '-V'):
        print(f"llmfs v{VERSION}"); sys.exit(0)
    if arg in ('--help', '-h'):
        print(f"llmfs v{VERSION}  —  LLM Filter Scanner")
        print("Использование: python3 llmfs091.py [--version] [--help]")
        sys.exit(0)

# ══════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════
class C:
    RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'; CYAN='\033[96m'
    MAGENTA='\033[95m'; WHITE='\033[97m'; GRAY='\033[90m'; BOLD='\033[1m'; RESET='\033[0m'

def clr(t, *cc): return ''.join(cc) + str(t) + C.RESET
def pause(m=None):
    msg = m if m is not None else t("  Нажмите Enter для продолжения...")
    try: input(clr(f"\n{msg}", C.GRAY))
    except: pass

# ══════════════════════════════════════════════════════════════════════
#  READLINE
# ══════════════════════════════════════════════════════════════════════
try:
    import readline
    def _path_completer(text, state):
        expanded = os.path.expanduser(text)
        matches = _glob.glob(expanded + '*')
        results = [m + ('/' if os.path.isdir(m) else '') for m in sorted(matches)]
        try: return results[state]
        except IndexError: return None
    readline.set_completer_delims('\t\n')
    readline.set_completer(_path_completer)
    readline.parse_and_bind("tab: complete")
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

# ══════════════════════════════════════════════════════════════════════
#  ПУТИ
# ══════════════════════════════════════════════════════════════════════
LLMFSC_DIR       = Path.home() / "Documents" / "llmfs"
DEFAULT_LOG_DIR  = LLMFSC_DIR / "LLM_logs"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "llm_monitor.log"
STOPWORDS_FILE   = LLMFSC_DIR / "stopwords.md"
WHITELIST_FILE   = LLMFSC_DIR / "whitelist.md"
SERVICES_FILE    = LLMFSC_DIR / "services.json"
PROFILES_FILE    = LLMFSC_DIR / "profiles.json"
STOPWORDS_FILE_OLD  = Path(__file__).parent / "stopwords.txt"
SCAN_HISTORY_FILE   = LLMFSC_DIR / "scan_history.json"
CONFIG_FILE         = LLMFSC_DIR / "config.json"
HISTORY_MAX         = 10

# ══════════════════════════════════════════════════════════════════════
#  ЯЗЫК / LANGUAGE
# ══════════════════════════════════════════════════════════════════════
_LANG = "ru"   # "ru" | "en"

_EN: dict = {
    # ── pause ────────────────────────────────────────────────────────────
    "  Нажмите Enter для продолжения...":   "  Press Enter to continue...",
    # ── main menu ────────────────────────────────────────────────────────
    "  Выбери режим:":                      "  Select mode:",
    "Сканирование файлов и папок":          "File & folder scan",
    "← файлы, папки, .gguf, текст":        "← files, folders, .gguf, text",
    "Сканирование AI-моделей":             "AI model scan",
    "← автопоиск Ollama, LM Studio…":      "← auto-detect Ollama, LM Studio…",
    "← перехват ответов в реальном времени": "← intercepts responses in real time",
    "Мониторинг логов ›":                  "Log monitoring ›",
    "← journalctl, лог-файлы":            "← journalctl, log files",
    "Профили ›":                           "Profiles ›",
    "Библиотека сервисов ›":              "Service library ›",
    "Отчеты и данные ›":                   "Reports & data ›",
    "🌐  Language / Язык":                 "🌐  Language / Язык",
    "🚪  Выход":                           "🚪  Exit",
    "Ваш выбор [0-7]: ":                  "Your choice [0-7]: ",
    # ── hdr ──────────────────────────────────────────────────────────────
    "LLM FILTER SCANNER":                  "LLM FILTER SCANNER",
    "Анализатор AI-сервисов":             "AI Service Analyzer",
    "Статика • Прокси-инспектор • Мониторинг • Профили • Библиотека":
        "Static • Proxy-inspector • Monitoring • Profiles • Library",
    "стоп-слова не загружены":            "stop words not loaded",
    "Найдено: ":                           "Detected: ",
    "Сервисов не обнаружено":             "No services detected",
    "Поиск сервисов...":                  "Scanning for services...",
    "Алертов: ":                           "Alerts: ",
    # ── reports_menu ─────────────────────────────────────────────────────
    "Отчеты и данные":                     "Reports & data",
    "  Поддержка sudo — имеется":          "  sudo support — available",
    "  Отчётов пока нет.":                 "  No reports yet.",
    "💾  Сохранить отчёт текущей сессии":  "💾  Save current session report",
    "Просмотреть отчёт №N":               "View report #N",
    "Удалить №N":                          "Delete #N",
    "d1 3 5  d5-20  dall":                "d1 3 5  d5-20  dall",
    "📁  Каталог файлов данных":          "📁  Data file catalog",
    "Назад":                              "Back",
    "  Действие: ":                       "  Action: ",
    "  ℹ️  Отчёт этой сессии уже сохранён.": "  ℹ️  Session report already saved.",
    "  Повторное сохранение создаст дубликат.": "  Saving again will create a duplicate.",
    "  Всё равно сохранить ещё раз? [y/N]: ": "  Save again anyway? [y/N]: ",
    "  Неверный формат. Примеры: d3  d1 3 5  d5-20  dall":
        "  Invalid format. Examples: d3  d1 3 5  d5-20  dall",
    "  Нет файлов для удаления.":          "  No files to delete.",
    "  Отмена.":                           "  Cancelled.",
    "  Неверный номер.":                   "  Invalid number.",
    "  Неверный ввод.":                    "  Invalid input.",
    # ── catalog ──────────────────────────────────────────────────────────
    "Каталог данных":                      "Data catalog",
    "  Папка данных не существует: ":     "  Data folder does not exist: ",
    # ── profiles / stop words / whitelist ────────────────────────────────
    "Профили":                             "Profiles",
    "  Поддержка sudo — имеется":          "  sudo support — available",
    "  Активный: ":                        "  Active: ",
    "✏️  Стоп-слова":                      "✏️  Stop words",
    "🚫  Белый список":                    "🚫  Whitelist",
    " слов":                              " words",
    " записей":                           " entries",
    "Стоп-слова":                          "Stop words",
    "  Файл : ":                          "  File : ",
    "  Слов : ":                          "  Words: ",
    "  ⚠️  Файл не найден: ":              "  ⚠️  File not found: ",
    "  Стоп-слова не активны.":            "  Stop words are inactive.",
    "  Создать файл (3 шага)":            "  Create file (3 steps)",
    "  Просмотреть список":               "  View list",
    "  Добавить слово/фразу":             "  Add word/phrase",
    "  Восстановить слова по умолчанию":  "  Restore default words",
    "← только отсутствующие":            "← only missing ones",
    "  Открыть в редакторе":             "  Open in editor",
    "q":                                  "q",
    "  Новая фраза: ":                    "  New phrase: ",
    "  Уже есть в списке.":               "  Already in list.",
    "  Номер для удаления: ":             "  Number to delete: ",
    "  Все слова по умолчанию уже есть в списке.":
        "  All default words are already in the list.",
    "Белый список":                        "Whitelist",
    "  Записи из этого списка НЕ вызывают алертов.":
        "  Entries in this list do NOT trigger alerts.",
    "  Все алерты активны.":              "  All alerts active.",
    "  Добавить запись":                   "  Add entry",
    "← URL, домен, IP или часть строки":  "← URL, domain, IP or substring",
    "  Новая запись: ":                   "  New entry: ",
    "  Записей : ":                       "  Entries: ",
    "  ⚠️  Файл не найден: ":             "  ⚠️  File not found: ",
    # ── logs menu ────────────────────────────────────────────────────────
    "Мониторинг логов":                    "Log monitoring",
    "🔴  Journalctl":                      "🔴  Journalctl",
    "       Мониторинг системного журнала сервиса в реальном времени.":
        "       Monitors system service journal in real time.",
    "       Сценарий: сервис запущен, нужно поймать подозрительные":
        "       Scenario: service running, catch suspicious",
    "       системные вызовы, сетевые подключения в метаданных.":
        "       system calls, network connections in metadata.",
    "📄  Лог-файл":                        "📄  Log file",
    "       Мониторинг произвольного .log файла (tail -f).":
        "       Monitor any .log file (tail -f).",
    "       Сценарий: сервис пишет лог на диск, хочешь видеть":
        "       Scenario: service writes log to disk, watch",
    "       алерты по мере появления новых строк.":
        "       alerts as new lines appear.",
    "  Выбор [0-2]: ":                    "  Choice [0-2]: ",
    "  Journalctl — мониторинг системного журнала\n":
        "  Journalctl — system journal monitoring\n",
    "  Читает journalctl -u <сервис> -f и сканирует каждую строку.":
        "  Reads journalctl -u <service> -f and scans each line.",
    "  Ctrl+C — остановить.\n":           "  Ctrl+C — stop.\n",
    "  Сервисы:":                         "  Services:",
    "  Другой сервис":                    "  Other service",
    "  Отмена":                           "  Cancel",
    "  Лог-файл — мониторинг файла в реальном времени\n":
        "  Log file — real-time file monitoring\n",
    "  Читает файл по мере его роста (как tail -f).":
        "  Reads file as it grows (like tail -f).",
    "  В другом терминале можно перенаправить journalctl:":
        "  In another terminal redirect journalctl:",
    # ── services menu ────────────────────────────────────────────────────
    "Библиотека сервисов":                "Service library",
    "  Файл: ":                           "  File: ",
    "  GitHub URL: не настроен":          "  GitHub URL: not configured",
    "⬇️  Обновить с GitHub":              "⬇️  Update from GitHub",
    "🔗  Настроить URL обновления":       "🔗  Configure update URL",
    "  Текущий URL: ":                    "  Current URL: ",
    "  Пример: https://raw.githubusercontent.com/user/repo/main/services.json":
        "  Example: https://raw.githubusercontent.com/user/repo/main/services.json",
    "  Enter без ввода — отмена.":        "  Empty Enter — cancel.",
    "  Новый URL (0 — отмена): ":         "  New URL (0 — cancel): ",
    "  ✅ URL сохранён.":                 "  ✅ URL saved.",
    # ── folder picker ────────────────────────────────────────────────────
    "  Найдено автоматически:":           "  Detected automatically:",
    "  Недавние папки:":                  "  Recent folders:",
    "h":                                  "h",
    "n":                                  "n",
    # ── log file picker ──────────────────────────────────────────────────
    "  Найденные лог-файлы:":             "  Log files found:",
    "  Лог-файлы не найдены автоматически.": "  Log files not found automatically.",
    "  Ввести путь вручную? [y/0]: ":     "  Enter path manually? [y/0]: ",
    # ── AI models menu ───────────────────────────────────────────────────
    "  [*] Поиск AI-моделей...":          "  [*] Searching for AI models...",
    "  ✅ Ollama — установленные модели:": "  ✅ Ollama — installed models:",
    "  Найденные папки моделей:":          "  Model folders found:",
    "  Указать путь вручную":             "  Enter path manually",
    "  Папки моделей не найдены автоматически.": "  Model folders not found automatically.",
    "  Популярные модели (справочно):":   "  Popular models (reference):",
    # ── proxy ────────────────────────────────────────────────────────────
    "  Выбери AI-сервис:":               "  Select AI service:",
    "✅ найден":                          "✅ detected",
    "⬜ не найден":                       "⬜ not found",
    "  Настроить вручную":               "  Configure manually",
    "  Назад":                           "  Back",
    "  Выбор: ":                         "  Choice: ",
    "  Выбор порта прокси":             "  Proxy port selection",
    "  [*] Проверка ":                   "  [*] Checking ",
    "  ✅  запущен на порту ":            "  ✅  running on port ",
    "  ⚠️   не обнаружен на порту ":     "  ⚠️   not found on port ",
    "  Что делаем?":                     "  What now?",
    "  Запустить ":                      "  Start ",
    " автоматически":                    " automatically",
    "  Запущу самостоятельно  (показать инструкцию)":
        "  I'll start it myself  (show instructions)",
    "  Отмена":                          "  Cancel",
    "  [*] Запускаю ":                   "  [*] Starting ",
    " не ответил за 8 сек. Продолжаем.": " did not respond in 8 sec. Continuing.",
    "  ── Инструкция ──────────────────────────────────────────────":
        "  ── Instructions ───────────────────────────────────────────",
    "  1. Запусти ":                     "  1. Start ",
    " в отдельном терминале.":           " in a separate terminal.",
    "  2. Подключи клиент через прокси:": "  2. Connect client through proxy:",
    "  ── Что такое Open WebUI? (необязательно) ───────────────────":
        "  ── What is Open WebUI? (optional) ──────────────────────────",
    "  Open WebUI — веб-интерфейс для локальных AI, как ChatGPT, но офлайн.":
        "  Open WebUI — web interface for local AI, like ChatGPT but offline.",
    "  Открывается в браузере: история чатов, файлы, несколько моделей.":
        "  Opens in browser: chat history, files, multiple models.",
    "  Устанавливается отдельно. Если не используешь — пропусти.":
        "  Installed separately. Skip if you don't use it.",
    "  Если используешь Open WebUI:":    "  If you use Open WebUI:",
    "  ────────────────────────────────────────────────────────────":
        "  ────────────────────────────────────────────────────────────",
    "  Нажми Enter когда сервис будет запущен...":
        "  Press Enter when service is running...",
    "  Запустить прокси всё равно? [y/N]: ": "  Start proxy anyway? [y/N]: ",
    # ── scan output ──────────────────────────────────────────────────────
    "  [*] Статическое сканирование: ":  "  [*] Static scan: ",
    "  [!] Путь не найден: ":            "  [!] Path not found: ",
    "  [*] Файлов найдено: ":            "  [*] Files found: ",
    "  [✓] Готово. Проверено файлов: ":  "  [✓] Done. Files scanned: ",
    # ── report markdown ──────────────────────────────────────────────────
    "# LLM Filter Scanner — Отчёт сессии": "# LLM Filter Scanner — Session Report",
    "**Дата:**":                          "**Date:**",
    "**Версия:**":                        "**Version:**",
    "**Всего алертов:**":                 "**Total alerts:**",
    "## Статистика":                      "## Statistics",
    "| Уровень | Количество |":           "| Level | Count |",
    "|---------|------------|":           "|-------|-------|",
    "## Алерты":                          "## Alerts",
    "**Время:**":                         "**Time:**",
    "**Источник:**":                      "**Source:**",
    "**Место:**":                         "**Location:**",
    "**Детали:**":                        "**Details:**",
    "## Итоги сессии":                    "## Session summary",
    "**Конец:**":                         "**End:**",
    # ── lang menu ────────────────────────────────────────────────────────
    "  1. Русский  ← текущий":           "  1. Русский  ← current",
    "  2. English  ← текущий":           "  2. English  ← current",
    "  Выбор [1/2/0]: ":                 "  Choice [1/2/0]: ",
    "  ✅ Язык сохранён.":               "  ✅ Language saved.",
    "  Уже выбран.":                     "  Already selected.",
    # ── v0.9.1 additions ─────────────────────────────────────────────────
    "URL телеметрии":                    "URL telemetry",
    "URL (проверьте)":                   "URL (check)",
    "  Ищет подозрительные паттерны в файлах моделей (GGUF и др.)\n":
        "  Searches for suspicious patterns in model files (GGUF etc.)\n",
    "  Прокси-инспектор — перехват ответов AI-сервиса":
        "  Proxy inspector — intercept AI service responses",
    "  ⚙️  Как подключить клиент:":      "  ⚙️  How to connect client:",
    "  Все ответы сканируются в реальном времени.\n":
        "  All responses are scanned in real time.\n",
    "  [*] Прокси остановлен.":          "  [*] Proxy stopped.",
    "  [*] Прервано, возврат в меню...": "  [*] Interrupted, returning to menu...",
    "  Нажмите Enter для возврата в меню...":
        "  Press Enter to return to menu...",
    "  Прервано. Сохраняю...":           "  Interrupted. Saving...",
    "  Указать порты вручную":           "  Configure ports manually",
    "  Укажи путь вручную или настрой сервис на запись логов.":
        "  Enter path manually or configure the service to write logs.",
}

def t(s: str, **kw) -> str:
    """Return translated string for current language. Falls back to Russian."""
    if _LANG == "en":
        out = _EN.get(s, s)
        return out.format(**kw) if kw else out
    return s.format(**kw) if kw else s

def load_lang():
    global _LANG
    # --lang flag overrides config
    for i, a in enumerate(sys.argv[1:], 1):
        if a in ("--lang", "-l") and i < len(sys.argv):
            val = sys.argv[i + 1].lower()
            if val in ("ru", "en"):
                _LANG = val; return
        if a.startswith("--lang="):
            val = a.split("=", 1)[1].lower()
            if val in ("ru", "en"):
                _LANG = val; return
    if CONFIG_FILE.exists():
        try:
            d = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if d.get("lang") in ("ru", "en"):
                _LANG = d["lang"]
        except Exception: pass

def save_lang(lang: str):
    global _LANG
    _LANG = lang
    ensure_dir(LLMFSC_DIR)
    cfg = {}
    if CONFIG_FILE.exists():
        try: cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception: pass
    cfg["lang"] = lang
    try: CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception: pass

def lang_menu():
    subprocess.run(['clear'])
    print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN, C.BOLD))
    print(clr(f"║   Language / Язык — LLM Filter Scanner v{VERSION}       ║", C.CYAN, C.BOLD))
    print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN, C.BOLD))
    print()
    r1 = clr(" ← " + t("текущий"), C.GREEN) if _LANG == "ru" else ""
    r2 = clr(" ← " + t("текущий"), C.GREEN) if _LANG == "en" else ""
    print(f"  {clr('1', C.CYAN, C.BOLD)}. Русский{r1}")
    print(f"  {clr('2', C.CYAN, C.BOLD)}. English{r2}")
    print(clr("  ──────────────────────────────────────────────────", C.GRAY))
    print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('Назад')}")
    try: ch = input(clr(t("  Выбор [1/2/0]: "), C.CYAN)).strip()
    except (KeyboardInterrupt, EOFError): return
    if ch == '1':
        if _LANG == "ru": print(clr("  " + t("  Уже выбран."), C.GRAY))
        else: save_lang("ru"); print(clr("  ✅ Язык: Русский", C.GREEN))
        pause()
    elif ch == '2':
        if _LANG == "en": print(clr("  " + t("  Уже выбран."), C.GRAY))
        else: save_lang("en"); print(clr("  ✅ Language: English", C.GREEN))
        pause()

def resolve_path(p): return Path(p).expanduser().resolve()
def ensure_dir(path):
    try: path.mkdir(parents=True, exist_ok=True); return True
    except Exception as e:
        print(clr(f"  [!] Не удалось создать папку {path}: {e}", C.RED)); return False

# ── История папок сканирования ────────────────────────────────────────
def load_scan_history() -> list:
    if SCAN_HISTORY_FILE.exists():
        try: return json.loads(SCAN_HISTORY_FILE.read_text(encoding='utf-8'))
        except Exception: pass
    return []

def _save_scan_history(paths: list):
    ensure_dir(LLMFSC_DIR)
    try: SCAN_HISTORY_FILE.write_text(json.dumps(paths, ensure_ascii=False, indent=2),
                                       encoding='utf-8')
    except Exception: pass

def add_to_scan_history(path_str: str):
    hist = load_scan_history()
    if path_str in hist: hist.remove(path_str)
    hist.insert(0, path_str)
    _save_scan_history(hist[:HISTORY_MAX])

def ask_folder_with_history(prompt="Папка для сканирования"):
    """Выбор папки: авто-найденные папки сервисов → история → ввод вручную."""
    entries = []  # list of (label, path_str)

    # 1. Авто-найденные папки AI-сервисов
    auto = _find_model_dirs()
    if auto:
        print(clr("\n" + t("  Найдено автоматически:"), C.YELLOW, C.BOLD))
        for svc_name, svc_path in auto:
            label = f"📁 {svc_path}  {clr(f'({svc_name})', C.GRAY)}"
            entries.append((label, str(svc_path)))
            print(f"  {clr(str(len(entries)), C.CYAN, C.BOLD)}. {label}")

    # 2. Недавние папки из истории (без дублей с авто)
    hist = load_scan_history()
    auto_paths = {str(p) for _, p in auto}
    hist_clean = [p for p in hist if p not in auto_paths]
    if hist_clean:
        recent_lbl = "  Recent folders:" if _LANG == "en" else "  Недавние папки:"
        print(clr("\n" + recent_lbl, C.WHITE, C.BOLD))
        for p in hist_clean:
            mark = clr("✅", C.GREEN) if Path(p).is_dir() else clr("⚠️ ", C.YELLOW)
            entries.append((f"{mark} {p}", p))
            print(f"  {clr(str(len(entries)), C.CYAN, C.BOLD)}. {mark} {p}")

    # 3. Домашняя папка + ручной ввод + отмена
    home_str = str(Path.home())
    home_lbl = "Home folder" if _LANG == "en" else "Домашняя папка"
    manual_lbl = "Enter path manually" if _LANG == "en" else "Указать путь вручную"
    cancel_lbl = "Cancel" if _LANG == "en" else "Отмена"
    print(f"\n  {clr('h', C.CYAN, C.BOLD)}. 🏠 {home_lbl} ({home_str})")
    print(f"  {clr('n', C.CYAN, C.BOLD)}. ✏️  {manual_lbl}")
    print(f"  {clr('0', C.CYAN, C.BOLD)}. {cancel_lbl}")

    if not entries:
        # Ничего не найдено — сразу в браузер
        p = ask_path(prompt, mode="dir")
        if p: add_to_scan_history(p)
        return p

    suffix = f"1-{len(entries)}/" if len(entries) > 1 else "1/"
    choice_lbl = "Choice" if _LANG == "en" else "Выбор"
    try:
        ch = input(clr(f"\n  {choice_lbl} [{suffix}h/n/0]: ", C.CYAN)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        return None

    if ch in ('0', ''):
        return None

    if ch == 'h':
        add_to_scan_history(home_str)
        return home_str

    if ch.isdigit():
        idx = int(ch) - 1
        if 0 <= idx < len(entries):
            chosen = entries[idx][1]
            add_to_scan_history(chosen)
            return chosen

    # 'n' или неизвестный ввод — браузер
    p = ask_path(prompt, mode="dir")
    if p: add_to_scan_history(p)
    return p

# ══════════════════════════════════════════════════════════════════════
#  АВТО-ОБНАРУЖЕНИЕ ЛОГ-ФАЙЛОВ
# ══════════════════════════════════════════════════════════════════════
_SERVICE_LOG_PATHS = {
    "Ollama":    [Path.home()/".ollama"/"logs"/"server.log",
                  Path("/var/log/ollama/server.log"),
                  Path("/var/log/ollama.log")],
    "LM Studio": [Path.home()/".lmstudio"/"logs"/"lmstudio.log",
                  Path.home()/".cache"/"lm-studio"/"logs"/"lmstudio.log"],
    "Jan":       [Path.home()/".local"/"share"/"jan"/"logs"/"app.log",
                  Path.home()/"jan"/"logs"/"app.log"],
    "LocalAI":   [Path("/var/log/localai.log"),
                  Path("/tmp/localai.log")],
    "KoboldCpp": [Path.home()/"koboldcpp"/"koboldcpp.log",
                  Path.home()/".koboldcpp"/"koboldcpp.log"],
    "TabbyML":   [Path.home()/".tabby"/"logs"/"tabby.log"],
    "llama.cpp": [Path.home()/"llama.cpp"/"llama.log"],
}

def _find_log_files():
    """Возвращает список (имя_сервиса, путь) для существующих лог-файлов."""
    found = []
    for svc_name, paths in _SERVICE_LOG_PATHS.items():
        for p in paths:
            if p.exists() and p.is_file():
                found.append((svc_name, p))
                break
    return found

def ask_logfile_with_hints(prompt="Лог-файл"):
    """Выбор лог-файла: авто-найденные → дефолт → ввод вручную."""
    entries = []

    # Авто-найденные лог-файлы AI-сервисов
    auto = _find_log_files()
    if auto:
        print(clr("\n" + t("  Найдено автоматически:"), C.YELLOW, C.BOLD))
        for svc_name, svc_path in auto:
            sz = svc_path.stat().st_size
            sz_str = f"{sz//1024}K" if sz < 1024*1024 else f"{sz//1024//1024}M"
            label = f"📄 {svc_path}  {clr(f'({svc_name}, {sz_str})', C.GRAY)}"
            entries.append(str(svc_path))
            print(f"  {clr(str(len(entries)), C.CYAN, C.BOLD)}. {label}")

    # Дефолтный файл — если существует и не в списке
    if DEFAULT_LOG_FILE.exists() and str(DEFAULT_LOG_FILE) not in entries:
        sz = DEFAULT_LOG_FILE.stat().st_size
        sz_str = f"{sz//1024}K" if sz < 1024*1024 else f"{sz//1024//1024}M"
        entries.append(str(DEFAULT_LOG_FILE))
        print(f"  {clr(str(len(entries)), C.CYAN, C.BOLD)}. 📄 {DEFAULT_LOG_FILE}  "
              f"{clr(f'(дефолт, {sz_str})', C.GRAY)}")
    elif not entries:
        print(clr("\n" + t("  Лог-файлы не найдены автоматически."), C.GRAY))
        print(clr(t("  Укажи путь вручную или настрой сервис на запись логов."), C.GRAY))

    print(f"  {clr('n', C.CYAN, C.BOLD)}. ✏️  {t('  Указать путь вручную').strip()}")
    print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('  Отмена').strip()}")

    if entries:
        suffix = f"1-{len(entries)}/" if len(entries) > 1 else "1/"
        choice_lbl = "Choice" if _LANG == "en" else "Выбор"
        try:
            ch = input(clr(f"\n  {choice_lbl} [{suffix}n/0]: ", C.CYAN)).strip().lower()
        except (KeyboardInterrupt, EOFError):
            return None
        if ch in ('0', ''):
            return None
        if ch.isdigit():
            idx = int(ch) - 1
            if 0 <= idx < len(entries):
                return entries[idx]
        if ch == 'n':
            return ask_path(prompt, default=str(DEFAULT_LOG_FILE), mode="file")
        return None

    # Список пуст — ввод вручную или отмена
    try:
        ch = input(clr(t("  Ввести путь вручную? [y/0]: "), C.CYAN)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        return None
    if ch in ('0', ''):
        return None
    return ask_path(prompt, default=str(DEFAULT_LOG_FILE), mode="file")

# ══════════════════════════════════════════════════════════════════════
#  БИБЛИОТЕКА AI-СЕРВИСОВ
# ══════════════════════════════════════════════════════════════════════
DEFAULT_SERVICES = [
    {"name": "Ollama",    "host": "localhost", "port": 11434, "proxy_port": 11435,
     "check_path": "/api/tags",   "api_paths": ["/api/generate", "/api/chat"],
     "format": "ollama",  "start_cmd": ["ollama", "serve"]},
    {"name": "LM Studio", "host": "localhost", "port": 1234,  "proxy_port": 1235,
     "check_path": "/v1/models",  "api_paths": ["/v1/chat/completions"],
     "format": "openai",  "start_cmd": []},
    {"name": "LocalAI",   "host": "localhost", "port": 8080,  "proxy_port": 8081,
     "check_path": "/v1/models",  "api_paths": ["/v1/chat/completions", "/v1/completions"],
     "format": "openai",  "start_cmd": []},
    {"name": "llama.cpp", "host": "localhost", "port": 8080,  "proxy_port": 8081,
     "check_path": "/health",     "api_paths": ["/completion", "/v1/chat/completions"],
     "format": "llamacpp","start_cmd": []},
    {"name": "Jan",       "host": "localhost", "port": 1337,  "proxy_port": 1338,
     "check_path": "/v1/models",  "api_paths": ["/v1/chat/completions"],
     "format": "openai",  "start_cmd": []},
    {"name": "KoboldCpp", "host": "localhost", "port": 5001,  "proxy_port": 5002,
     "check_path": "/api/v1/info","api_paths": ["/api/v1/generate"],
     "format": "kobold",  "start_cmd": []},
    {"name": "TabbyML",   "host": "localhost", "port": 8080,  "proxy_port": 8081,
     "check_path": "/v1/health",  "api_paths": ["/v1/completions"],
     "format": "openai",  "start_cmd": []},
]

_services_cache = None

def load_services():
    global _services_cache, SERVICES_UPDATE_URL
    if _services_cache is not None:
        return _services_cache
    if SERVICES_FILE.exists():
        try:
            data = json.loads(SERVICES_FILE.read_text(encoding='utf-8'))
            _services_cache = data.get("services", DEFAULT_SERVICES)
            if data.get("update_url"):
                SERVICES_UPDATE_URL = data["update_url"]
            return _services_cache
        except Exception:
            pass
    _services_cache = list(DEFAULT_SERVICES)
    return _services_cache

def save_services(services):
    global _services_cache
    ensure_dir(LLMFSC_DIR)
    data = {"version": VERSION, "updated": datetime.now().isoformat(),
            "services": services}
    if SERVICES_UPDATE_URL:
        data["update_url"] = SERVICES_UPDATE_URL
    content = json.dumps(data, ensure_ascii=False, indent=2)
    if not SERVICES_FILE.exists():
        if not _file_touch(SERVICES_FILE): return
        _file_chmod(SERVICES_FILE)
        _file_write(SERVICES_FILE, content)
    else:
        if not _file_write_safe(SERVICES_FILE, content):
            print(clr("  ❌ services.json не сохранён.", C.RED)); return
    _services_cache = services

def save_update_url(url: str):
    """Сохраняет URL обновления в services.json без перезаписи списка сервисов."""
    global SERVICES_UPDATE_URL
    SERVICES_UPDATE_URL = url
    save_services(load_services())

def update_services_from_github():
    if not SERVICES_UPDATE_URL:
        print(clr("\n  ⚠️  URL для обновления не настроен.", C.YELLOW))
        print(clr("  Используй 'c. Настроить URL' в меню библиотеки сервисов.", C.GRAY))
        pause(); return
    try:
        import urllib.request
        print(clr("\n  [*] Загрузка обновления...", C.GRAY))
        with urllib.request.urlopen(SERVICES_UPDATE_URL, timeout=10) as r:
            data = json.loads(r.read().decode('utf-8'))
        services = data.get("services", [])
        if not services:
            print(clr("  [!] Пустой список в обновлении.", C.RED)); pause(); return
        save_services(services)
        print(clr(f"  ✅ Обновлено. Сервисов: {len(services)}", C.GREEN))
    except Exception as e:
        print(clr(f"  [!] Ошибка загрузки: {e}", C.RED))
    pause()

# ══════════════════════════════════════════════════════════════════════
#  АВТО-ОБНАРУЖЕНИЕ (фоновый поток при запуске)
# ══════════════════════════════════════════════════════════════════════
_detected_services = []
_detection_done    = False

def _detect_bg():
    global _detected_services, _detection_done
    found = []
    for svc in load_services():
        try:
            conn = http.client.HTTPConnection(
                svc.get("host", "localhost"), svc["port"], timeout=1)
            conn.request("GET", svc.get("check_path", "/"))
            resp = conn.getresponse(); conn.close()
            if resp.status < 500:
                found.append(svc)
        except Exception:
            pass
    _detected_services = found
    _detection_done    = True

def start_detection():
    threading.Thread(target=_detect_bg, daemon=True).start()

# ══════════════════════════════════════════════════════════════════════
#  ИНТЕРАКТИВНЫЙ БРАУЗЕР ПУТЕЙ
# ══════════════════════════════════════════════════════════════════════
def _ls(path, max_items=30):
    try:
        items = sorted(Path(path).iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        dirs  = [i for i in items if i.is_dir()]
        files = [i for i in items if i.is_file()]
        shown = 0
        if dirs:
            print(clr("  📁 Папки:", C.CYAN))
            for d in dirs[:max_items]:
                print(f"     {clr(d.name+'/', C.CYAN)}"); shown += 1
        if files and shown < max_items:
            print(clr("  📄 Файлы:", C.GRAY))
            for f in files[:max_items - shown]:
                size = f.stat().st_size
                sz = f"{size//1024//1024}M" if size > 1024*1024 else f"{size//1024}K"
                print(f"     {clr(f.name, C.GRAY)}  {clr(sz, C.GRAY)}")
        total = len(dirs) + len(files)
        if total > max_items: print(clr(f"  ... ещё {total - max_items} элементов", C.GRAY))
    except PermissionError: print(clr("  [!] Нет доступа к папке.", C.RED))
    except Exception as e:  print(clr(f"  [!] {e}", C.RED))

def _suggest(text, cwd):
    if not text: return
    try:
        base = Path(text).expanduser()
        if not base.is_absolute(): base = cwd / text
        parent = base.parent if not str(text).endswith('/') else base
        prefix = base.name   if not str(text).endswith('/') else ''
        matches = [p for p in sorted(parent.iterdir())
                   if p.name.lower().startswith(prefix.lower())][:8]
        if matches:
            parts = [clr(m.name + ('/' if m.is_dir() else ''),
                         C.CYAN if m.is_dir() else C.GRAY) for m in matches]
            print(clr("  Подсказка: ", C.YELLOW) + "  ".join(parts))
    except Exception: pass

def ask_path(prompt, default="", mode="any", hints=None):
    cwd = Path.home()
    print()
    if hints:
        print(clr("  💡 Найдено:", C.YELLOW))
        for h in hints: print(f"     {clr('→', C.YELLOW)} {clr(str(h), C.CYAN)}")
    if default: print(clr(f"  По умолчанию: {default}", C.GRAY))
    if HAS_READLINE: print(clr("  [Tab] — автодополнение пути", C.GRAY))
    print(clr("  Команды: ls  cd <путь>  ..  ~  /", C.GRAY))
    print()
    while True:
        try:
            inp = input(clr(f"  {prompt} > ", C.CYAN)).strip().strip('"\'')
        except (KeyboardInterrupt, EOFError):
            print(); return str(default) if default else None
        if not inp:
            if default: return str(default)
            print(clr("  [!] Укажите путь или введите команду.", C.YELLOW)); continue
        if inp == '~':  cwd = Path.home(); print(clr(f"  → {cwd}", C.CYAN)); _ls(cwd); continue
        if inp == '/':  cwd = Path('/');   print(clr(f"  → {cwd}", C.CYAN)); _ls(cwd); continue
        if inp == '..': cwd = cwd.parent;  print(clr(f"  → {cwd}", C.CYAN)); _ls(cwd); continue
        if inp == 'ls' or inp.startswith('ls '):
            ls_arg = inp[3:].strip() if inp.startswith('ls ') else ''
            ls_p = (Path(ls_arg).expanduser() if ls_arg else cwd)
            if not ls_p.is_absolute(): ls_p = cwd / ls_p
            print(clr(f"\n  📂 {ls_p}", C.CYAN)); _ls(ls_p); continue
        if inp.startswith('cd ') or inp == 'cd':
            new_dir = inp[3:].strip() if len(inp) > 2 else ''
            if not new_dir: cwd = Path.home()
            else:
                new_p = Path(new_dir).expanduser()
                if not new_p.is_absolute(): new_p = cwd / new_p
                new_p = new_p.resolve()
                if new_p.is_dir(): cwd = new_p; print(clr(f"  → {cwd}", C.CYAN)); _ls(cwd)
                else: print(clr(f"  [!] Папка не найдена: {new_p}", C.RED))
            continue
        _suggest(inp, cwd)
        p = Path(inp).expanduser()
        if not p.is_absolute(): p = cwd / inp
        p = p.resolve()
        if mode == "dir":
            if p.is_dir(): return str(p)
            elif p.exists(): print(clr(f"  [!] Это файл, а не папка: {p}", C.RED))
            else:
                print(clr(f"  Папка не существует: {p}", C.YELLOW))
                try: yn = input(clr("  Создать? [y/N]: ", C.CYAN)).strip().lower()
                except (KeyboardInterrupt, EOFError): yn = 'n'
                if yn == 'y' and ensure_dir(p): return str(p)
        elif mode == "file":
            if p.is_file(): return str(p)
            elif p.is_dir(): print(clr(f"  [!] Это папка, а не файл: {p}", C.RED))
            else: return str(p)
        else:
            if p.exists(): return str(p)
            else:
                print(clr(f"  [!] Путь не найден: {p}", C.RED))
                print(clr(f"  Текущая папка: {cwd}", C.GRAY)); _ls(cwd)

# ══════════════════════════════════════════════════════════════════════
#  СТОП-СЛОВА
# ══════════════════════════════════════════════════════════════════════
SW_HEADER = (
    f"# Стоп-слова — LLM Filter Scanner v{VERSION}\n\n"
    "> Файл: `~/Documents/llmfs/stopwords.md`  \n"
    "> Одно слово/фраза на строку.  \n"
    "> Строки с `#`, `>` — комментарии, не сканируются.\n\n"
)
DEFAULT_STOPWORDS = """\
## 1. Отказы и идентификация (EN)

as an ai
as a language model
i cannot
i can't
i am unable
i apologize, sorry, but
i don't have personal
i am just a
i do not have feelings

## 1. Отказы и идентификация (RU)

как искусственный интеллект
как языковая модель
я не могу
я не запрограммирована
я не запрограммирован
извините, но
к сожалению
я всего лишь
я не обладаю чувствами

## 2. Цензура, этика, безопасность (EN)

ethical guidelines
safety policy
against my programming
violates safety
not appropriate
unethical
illegal
harmful
content policy
restricted
forbidden
censored

## 2. Цензура, этика, безопасность (RU)

этические нормы
политика безопасности
нарушает правила
недопустимо
незаконно
причинить вред
пропаганда
оскорбительный контент
противоречит моим инструкциям

## 3. Телеметрия и сеть (EN)

phone home
call home
send report
telemetry
google-analytics
tracking
webhook
api.openai.com
send_data

## 3. Телеметрия и сеть (RU)

отправка данных
сбор статистики
отчет об ошибке
отправить логи

## 4. Утечка системного промпта (EN)

you are a helpful assistant
ignore previous instructions
system prompt
knowledge cutoff
you must adhere to

## 4. Утечка системного промпта (RU)

вы полезный помощник
ты ии-ассистент
игнорируй предыдущие инструкции
база знаний ограничена
системное сообщение
"""

WL_HEADER = (
    f"# Белый список — LLM Filter Scanner v{VERSION}\n\n"
    "> Файл: `~/Documents/llmfs/whitelist.md`  \n"
    "> Записи, содержащие эти строки, НЕ вызывают алерт.  \n"
    "> Строки с `#`, `>` — комментарии.\n\n"
    "## Примеры (раскомментируй нужное)\n\n"
    "# localhost\n"
    "# 127.0.0.1\n"
    "# huggingface.co\n"
    "# arxiv.org\n\n"
)

def _read_words_from(path):
    words = []
    try:
        for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('>'):
                words.append(line.lower())
    except Exception: pass
    return words

def _read_words_from_string(text):
    words = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('>'):
            words.append(line.lower())
    return words

# ── sudo helpers ──────────────────────────────────────────────────────
def _sudo_ask_password():
    import getpass
    try:
        pwd = getpass.getpass(clr("  Пароль sudo (Enter = отмена): ", C.CYAN))
        return pwd if pwd else None
    except (KeyboardInterrupt, EOFError):
        print(); return None

def _sudo_run(cmd_args, password):
    try:
        result = subprocess.run(["sudo", "-S"] + cmd_args,
            input=password + "\n", capture_output=True, text=True, timeout=15)
        if result.returncode == 0: return True, ""
        msg = (result.stderr.strip().split('\n') or ["неверный пароль"])[-1]
        return False, msg
    except FileNotFoundError: return False, "sudo не найден"
    except Exception as e:    return False, str(e)

def _file_touch(f: Path) -> bool:
    ensure_dir(f.parent)
    try: f.touch(); return f.exists()
    except PermissionError: pass
    print(clr("  Нет прав — нужен sudo.", C.YELLOW))
    pwd = _sudo_ask_password()
    if pwd is None: return False
    ok, msg = _sudo_run(["touch", str(f)], pwd)
    if not ok or not f.exists():
        print(clr(f"  [!] sudo touch: {msg or 'файл не появился'}", C.RED)); return False
    import getpass as _gp
    _sudo_run(["chown", _gp.getuser(), str(f)], pwd)
    return True

def _file_chmod(f: Path) -> bool:
    try: os.chmod(f, 0o644); return True
    except PermissionError: pass
    print(clr("  Нет прав на chmod — нужен sudo.", C.YELLOW))
    pwd = _sudo_ask_password()
    if pwd is None: return False
    ok, msg = _sudo_run(["chmod", "644", str(f)], pwd)
    if ok: return True
    print(clr(f"  [!] sudo chmod: {msg}", C.RED)); return False

def _file_write(f: Path, content: str) -> bool:
    try:
        f.write_text(content, encoding='utf-8')
        if f.exists() and f.stat().st_size > 0: return True
        print(clr("  [!] Файл пуст после записи.", C.RED)); return False
    except PermissionError:
        print(clr("  [!] Нет прав на запись.", C.RED))
        print(clr("  Запусти: sudo chown $(whoami) " + str(f), C.YELLOW)); return False
    except Exception as e:
        print(clr(f"  [!] Ошибка записи: {e}", C.RED)); return False

def _file_delete(f: Path) -> bool:
    """Удаление файла с sudo если нужно. Всегда спрашивает подтверждение."""
    try:
        yn = input(clr(f"  Удалить {f.name}? [y/N]: ", C.CYAN)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print(); return False
    if yn != 'y':
        print(clr("  Отмена.", C.GRAY)); return False
    try:
        f.unlink(); return True
    except PermissionError: pass
    print(clr("  Нет прав — нужен sudo.", C.YELLOW))
    pwd = _sudo_ask_password()
    if pwd is None: return False
    ok, msg = _sudo_run(["rm", str(f)], pwd)
    if ok: return True
    print(clr(f"  [!] sudo rm: {msg}", C.RED)); return False

def _file_write_sudo(f: Path, content: str, pwd: str) -> bool:
    """Запись через temp-файл + sudo cp (когда plain write даёт PermissionError)."""
    import tempfile
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
                'w', encoding='utf-8', delete=False, suffix='.llmfs.tmp') as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        ok, msg = _sudo_run(["cp", tmp_path, str(f)], pwd)
        if ok:
            _sudo_run(["chmod", "644", str(f)], pwd)
            return True
        print(clr(f"  [!] sudo cp: {msg}", C.RED)); return False
    except Exception as e:
        print(clr(f"  [!] _file_write_sudo: {e}", C.RED)); return False
    finally:
        if tmp_path:
            try: Path(tmp_path).unlink()
            except Exception: pass

def _file_write_safe(f: Path, content: str) -> bool:
    """Запись файла; при PermissionError — запрашивает sudo и пишет через temp."""
    try:
        f.write_text(content, encoding='utf-8'); return True
    except PermissionError: pass
    print(clr("  Нет прав на запись — нужен sudo.", C.YELLOW))
    pwd = _sudo_ask_password()
    if pwd is None: return False
    return _file_write_sudo(f, content, pwd)

def create_md_file(f: Path, content: str, label: str) -> bool:
    print(clr(f"\n  Создание: {f}", C.CYAN, C.BOLD))
    print(clr("\n  ── Шаг 1/3: Создание файла ──────────────────────", C.YELLOW))
    if not _file_touch(f): print(clr("  ❌ Шаг 1 не выполнен.", C.RED)); return False
    print(clr("  ✅ Шаг 1 выполнен.", C.GREEN))
    print(clr("\n  ── Шаг 2/3: Права (644) ─────────────────────────", C.YELLOW))
    if not _file_chmod(f): print(clr("  ⚠️  Шаг 2 пропущен.", C.YELLOW))
    else: print(clr("  ✅ Шаг 2 выполнен.", C.GREEN))
    print(clr(f"\n  ── Шаг 3/3: Запись {label} ───────────────────────", C.YELLOW))
    if not _file_write(f, content): print(clr("  ❌ Шаг 3 не выполнен.", C.RED)); return False
    print(clr("  ✅ Шаг 3 выполнен.", C.GREEN))
    print(clr(f"\n  ✅ Готово: {f}", C.GREEN)); return True

def load_stopwords():
    words = _read_words_from(STOPWORDS_FILE) if STOPWORDS_FILE.exists() else []
    for old in [STOPWORDS_FILE_OLD, Path(__file__).parent / "stopwords.md"]:
        if old.exists() and old.resolve() != STOPWORDS_FILE.resolve():
            added = [w for w in _read_words_from(old) if w not in words]
            if added: words.extend(added)
    return words

def save_stopwords(words) -> bool:
    ok = _file_write(STOPWORDS_FILE, SW_HEADER + '\n'.join(words) + '\n')
    print(clr("  ✅ Сохранено.", C.GREEN) if ok
          else clr("  ❌ Не сохранено — список в памяти, но файл не изменён.", C.RED))
    return ok

def restore_default_stopwords() -> int:
    current = load_stopwords()
    missing = [w for w in _read_words_from_string(DEFAULT_STOPWORDS) if w not in current]
    if not missing: return 0
    save_stopwords(current + missing); return len(missing)

def load_whitelist():
    return _read_words_from(WHITELIST_FILE) if WHITELIST_FILE.exists() else []

STOP_WORDS = load_stopwords()
WHITELIST  = load_whitelist()

# ══════════════════════════════════════════════════════════════════════
#  ПАТТЕРНЫ
# ══════════════════════════════════════════════════════════════════════
PATTERN_IP    = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
PATTERN_URL   = re.compile(r'https?://[^\s"\'>]+')
PATTERN_CMD   = re.compile(
    r'(\.bat\b|\.sh\b|curl\b|wget\b|os\.system|subprocess\.|exec\(|eval\(|'
    r'shell=True|popen\(|/bin/bash|/bin/sh\b|powershell|CreateProcess|ShellExecute)',
    re.IGNORECASE)
PATTERN_AUTO  = re.compile(
    r'(crontab|schtasks|systemd.*enable|\.bashrc|\.bash_profile|\.zshrc|'
    r'HKLM.*Run|HKCU.*Run|/etc/init\.d|rc\.local|autostart)', re.IGNORECASE)
PATTERN_EXFIL = re.compile(
    r'(base64\.(encode|decode)|btoa|atob|zlib\.|gzip\.).*'
    r'(send|post|upload|transfer|transmit)', re.IGNORECASE)
PATTERN_SENS  = re.compile(
    r'(password|passwd|secret|api[_\-]?key|access[_\-]?token|private[_\-]?key|'
    r'\.ssh/|\.aws/credentials|/etc/shadow)\s*[=:]\s*["\'][^"\']{4,}', re.IGNORECASE)
PATTERN_OBFS  = re.compile(r'(\\x[0-9a-fA-F]{2}){6,}|(\\u[0-9a-fA-F]{4}){4,}')

TELEMETRY_KW = ['track','telemetry','analytics','beacon','metric','stat','report',
    'monitor','ping','collect','event','usage','diagnostic','crash','sentry',
    'datadog','newrelic','mixpanel','segment','amplitude','hotjar','bugsnag']

PRIVATE_NETS = [ipaddress.ip_network(n) for n in
    ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','0.0.0.0/8')]

def is_private(ip):
    try: a = ipaddress.ip_address(ip); return any(a in n for n in PRIVATE_NETS)
    except: return True

def is_telem_url(u): return any(k in u.lower() for k in TELEMETRY_KW)

def is_whitelisted(text):
    if not WHITELIST: return False
    tl = text.lower()
    return any(w in tl for w in WHITELIST)

SKIP_EXT = {'.bin','.gguf','.safetensors','.exe','.dll','.so','.pyc',
            '.jpg','.jpeg','.png','.gif','.mp3','.mp4','.zip','.tar','.gz','.7z'}
MAX_SIZE = 10 * 1024 * 1024

# ══════════════════════════════════════════════════════════════════════
#  АЛЕРТЫ
# ══════════════════════════════════════════════════════════════════════
alert_log, _lock = [], threading.Lock()
_session_report_saved = False          # защита от повторного сохранения отчёта
_proxy_inc_log = None  # Path к инкрементальному MD-логу прокси (None вне сессии)
SEV = {"CRITICAL": (C.RED+C.BOLD, "🔴"), "HIGH": (C.RED, "🟠"),
       "MEDIUM":   (C.YELLOW,     "🟡"), "INFO": (C.GRAY,"⚪")}

def _proxy_append_alert(entry: dict):
    """Дописывает один алерт в инкрементальный MD-лог прокси немедленно."""
    global _proxy_inc_log
    if _proxy_inc_log is None:
        return
    icon = SEV.get(entry['severity'], (C.WHITE, "?"))[1]
    ts = entry['time'][11:19]  # HH:MM:SS из isoformat
    block = (
        f"## [{ts}] {icon} {entry['severity']} — {entry['type']}\n"
        f"\n"
        f"- {t('**Источник:**')} {entry['source']}\n"
        f"- {t('**Место:**')} {entry['location']}\n"
        f"- {t('**Детали:**')} `{entry['detail'][:300]}`\n"
        f"\n"
        f"---\n"
        f"\n"
    )
    try:
        with open(_proxy_inc_log, 'a', encoding='utf-8') as f:
            f.write(block)
    except Exception:
        pass  # данные в памяти (alert_log) сохранены — лог вторичен

def _proxy_alert_counter():
    """Строка статуса [Алертов: 3 HIGH / 1 CRITICAL] — только в прокси-режиме."""
    if _proxy_inc_log is None:
        return
    cnt = {}
    for e in alert_log: cnt[e['severity']] = cnt.get(e['severity'], 0) + 1
    parts = []
    for sk in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        if cnt.get(sk, 0):
            col = SEV[sk][0]
            parts.append(clr(f"{cnt[sk]} {sk}", col))
    if parts:
        al_cnt_lbl = "Alerts" if _LANG == "en" else "Алертов"
        print(clr(f"  ╌╌╌ {al_cnt_lbl}: {' / '.join(parts)} ╌╌╌", C.GRAY))

def alert(src, typ, sev, loc, detail):
    col, icon = SEV.get(sev, (C.WHITE, "❓"))
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n  {icon} {clr(f'[{ts}] {sev}: {typ}', col)}")
    src_lbl = "Source  " if _LANG == "en" else "Источник"
    loc_lbl = "Location" if _LANG == "en" else "Место   "
    det_lbl = "Details " if _LANG == "en" else "Детали  "
    print(clr(f"     {src_lbl} : {src}", C.CYAN))
    print(clr(f"     {loc_lbl} : {loc}", C.YELLOW))
    print(clr(f"     {det_lbl} : {detail[:200]}", C.WHITE))
    entry = {"time": datetime.now().isoformat(),
             "source": src, "type": typ, "severity": sev, "location": loc, "detail": detail}
    with _lock:
        alert_log.append(entry)
        _proxy_append_alert(entry)  # ← инкрементальная запись (no-op если не в прокси)
        _proxy_alert_counter()      # ← строка статуса (no-op если не в прокси)

# ══════════════════════════════════════════════════════════════════════
#  СКАНИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════
def scan_line(line, loc, src):
    for m in PATTERN_IP.finditer(line):
        ip = m.group(0)
        if not is_private(ip) and not is_whitelisted(ip):
            alert(src, "Жёсткий IP (телеметрия?)", "HIGH", loc, ip)
    for m in PATTERN_URL.finditer(line):
        u = m.group(0)
        if is_whitelisted(u): continue
        alert(src, t("URL телеметрии") if is_telem_url(u) else t("URL (проверьте)"),
              "HIGH" if is_telem_url(u) else "INFO", loc, u[:120])
    if PATTERN_CMD.search(line):
        alert(src, "Системный вызов / скрипт", "HIGH", loc, line.strip()[:120])
    if PATTERN_AUTO.search(line):
        alert(src, "Механизм автозапуска", "HIGH", loc, line.strip()[:120])
    if PATTERN_EXFIL.search(line):
        alert(src, "Скрытая передача данных", "CRITICAL", loc, line.strip()[:120])
    if PATTERN_SENS.search(line):
        alert(src, "Утечка пароля/ключа", "HIGH", loc, line.strip()[:80] + "…")
    if PATTERN_OBFS.search(line):
        alert(src, "Обфускация кода", "HIGH", loc, line.strip()[:80] + "…")

def check_stopwords(line, src):
    ll = line.lower(); found = False
    for w in STOP_WORDS:
        if w in ll and not is_whitelisted(w):
            alert(src, "Корпоративный фильтр / Цензура", "MEDIUM", "Вывод модели",
                  f"Сработало: '{w}'\n     Текст: {line[:200]}")
            found = True
    return found

def scan_text(text, src, label=""):
    loc = label or src
    check_stopwords(text, src)
    for ln in text.splitlines():
        if ln.strip(): scan_line(ln, loc, src)

# ══════════════════════════════════════════════════════════════════════
#  GGUF
# ══════════════════════════════════════════════════════════════════════
def scan_gguf(path):
    try:
        with open(path, 'rb') as f:
            if f.read(4) != b'GGUF':
                alert("GGUF", "Неверная сигнатура (подмена?)", "HIGH", str(path), ""); return
            ver = struct.unpack('<I', f.read(4))[0]
            raw = f.read(512 * 1024)
        strings = [c.decode('ascii', 'replace') for c in re.findall(rb'[ -~]{8,}', raw)]
        pats = [
            (r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&()*+,;=%]+', "MEDIUM", "URL в метаданных"),
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b',                     "MEDIUM", "IP в метаданных"),
            (r'(?:bash|python|curl|wget|exec|eval|system)\s*\(',  "HIGH",   "Вызов команды"),
            (r'(?i)(?:telemetry|analytics|phone.home|call.home)', "HIGH",   "Телеметрия"),
            (r'(?:password|secret|api_key|token|private_key)',    "HIGH",   "Чувств. данные"),
        ]
        found = False
        for s in strings:
            for rgx, sev, desc in pats:
                for m in re.finditer(rgx, s, re.I):
                    mt = m.group(0)
                    if 'IP' in desc and is_private(mt): continue
                    if 'URL' in desc and not is_telem_url(mt): continue
                    if is_whitelisted(mt): continue
                    alert("GGUF", desc, sev, str(path), f"{mt[:80]}  ←  {s[:100]}")
                    found = True
        if not found:
            print(clr(f"  ✅ GGUF v{ver}: метаданные чистые — {path.name}", C.GREEN))
    except Exception as e:
        print(clr(f"  [!] Ошибка GGUF {path.name}: {e}", C.RED))

# ══════════════════════════════════════════════════════════════════════
#  СТАТИЧЕСКОЕ СКАНИРОВАНИЕ
# ══════════════════════════════════════════════════════════════════════
def static_scan(target_path):
    target = resolve_path(target_path)
    print(clr(f"\n  {t('  [*] Статическое сканирование: ').strip()} {target}", C.GREEN, C.BOLD))
    if not target.exists():
        print(clr(f"  {t('  [!] Путь не найден: ').strip()} {target}", C.RED)); return
    files = [target] if target.is_file() else [f for f in target.rglob("*") if f.is_file()]
    print(clr(f"  {t('  [*] Файлов найдено: ').strip()} {len(files)}", C.GRAY))
    scanned = 0
    for fp in sorted(files):
        if fp.suffix.lower() == '.gguf':
            scan_gguf(fp); scanned += 1; continue
        if fp.suffix.lower() in SKIP_EXT: continue
        try:
            if fp.stat().st_size > MAX_SIZE or fp.stat().st_size == 0: continue
            for ln, line in enumerate(
                    fp.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                src_tag = "STATIC" if _LANG == "en" else "СТАТИКА"
                pg_tag  = "ln"     if _LANG == "en" else "стр"
                scan_line(line, f"{fp} [{pg_tag}.{ln}]", src_tag)
            scanned += 1
            print(clr(f"  [ ] {fp.name:<60}", C.GRAY), end='\r')
        except: pass
    print(' ' * 70, end='\r')
    print(clr(f"  {t('  [✓] Готово. Проверено файлов: ').strip()} {scanned}", C.GREEN))

# ══════════════════════════════════════════════════════════════════════
#  СКАНИРОВАНИЕ AI-МОДЕЛЕЙ
# ══════════════════════════════════════════════════════════════════════
KNOWN_MODELS = ["tinyllama","llama2","llama3","llama3.1","llama3.2","mistral","mixtral",
    "phi","phi3","gemma","gemma2","qwen","qwen2","qwen2.5","codellama","deepseek-coder",
    "deepseek-r1","neural-chat","vicuna","orca-mini","dolphin-mistral","zephyr",
    "openchat","stablelm","falcon","nous-hermes","solar","yi","internlm"]

_SERVICE_MODEL_PATHS = {
    "Ollama":    [Path.home()/".ollama"/"models",
                  Path("/var/lib/ollama/models"),
                  Path("/var/lib/ollama"),
                  Path("/usr/share/ollama/models"),
                  Path("/opt/ollama/models")],
    "LM Studio": [Path.home()/".cache"/"lm-studio"/"models",
                  Path.home()/".lmstudio"/"models"],
    "LocalAI":   [Path.home()/".local"/"share"/"localai"/"models",
                  Path("/opt/localai/models"),
                  Path("/usr/local/lib/localai/models")],
    "llama.cpp": [Path.home()/"llama.cpp"/"models",
                  Path.home()/"llama-cpp"/"models",
                  Path("/opt/llama.cpp/models")],
    "Jan":       [Path.home()/"jan"/"models",
                  Path.home()/".jan"/"models"],
    "KoboldCpp": [Path.home()/"koboldcpp"/"models",
                  Path.home()/"KoboldCpp"/"models",
                  Path.home()/".koboldcpp"/"models"],
    "TabbyML":   [Path.home()/".tabby"/"models",
                  Path.home()/".local"/"share"/"tabby"/"models"],
}

def _find_model_dirs():
    found = []
    for svc_name, paths in _SERVICE_MODEL_PATHS.items():
        for p in paths:
            if p.exists():
                found.append((svc_name, p))
                break
    return found

def ai_models_menu():
    print(clr("\n" + t("  [*] Поиск AI-моделей..."), C.GRAY))
    try:
        r = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            lines = r.stdout.strip().splitlines()
            if len(lines) > 1:
                print(clr(t("  ✅ Ollama — установленные модели:"), C.GREEN))
                for l in lines[1:]:
                    p = l.split()
                    if p: print(f"     • {p[0]}")
    except Exception: pass

    found_dirs = _find_model_dirs()
    if found_dirs:
        print(clr("\n" + t("  Найденные папки моделей:"), C.GREEN))
        for i, (nm, p) in enumerate(found_dirs, 1):
            print(f"  {clr(str(i), C.CYAN, C.BOLD)}. {clr(nm, C.WHITE)} — {clr(str(p), C.GRAY)}")
        print(f"  {clr('m', C.CYAN, C.BOLD)}. {t('  Указать путь вручную').strip()}")
        print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('  Отмена').strip()}")
        try: ch = input(clr("\n" + t("  Выбор: "), C.CYAN)).strip()
        except (KeyboardInterrupt, EOFError): return None
        if ch == '0': return None
        if ch == 'm': return ask_path("Папка с моделями", mode="dir")
        try:
            idx = int(ch) - 1
            if 0 <= idx < len(found_dirs): return str(found_dirs[idx][1])
        except ValueError: pass
        return None
    else:
        print(clr("\n" + t("  Папки моделей не найдены автоматически."), C.YELLOW))
        print(clr(t("  Популярные модели (справочно):"), C.GRAY))
        for i in range(0, len(KNOWN_MODELS), 5):
            print("  " + "  ".join(clr(f"• {m}", C.GRAY) for m in KNOWN_MODELS[i:i+5]))
        return ask_path("Укажи путь к папке с моделями", mode="dir")

# ══════════════════════════════════════════════════════════════════════
#  ПРОВЕРКА И ЗАПУСК AI-СЕРВИСА
# ══════════════════════════════════════════════════════════════════════
def check_service_running(svc: dict) -> bool:
    try:
        conn = http.client.HTTPConnection(svc.get("host","localhost"), svc["port"], timeout=3)
        conn.request("GET", svc.get("check_path", "/"))
        resp = conn.getresponse(); conn.close()
        return resp.status < 500
    except Exception: return False

def ask_service_start(svc: dict, listen_port: int) -> bool:
    name = svc.get("name", "AI-сервис")
    port = svc["port"]
    print(clr(f"\n{t('  [*] Проверка ')}{name}...", C.GRAY))
    if check_service_running(svc):
        running_lbl = "running on port" if _LANG == "en" else "запущен на порту"
        print(clr(f"  ✅ {name} {running_lbl} {port}", C.GREEN)); return True

    not_found_lbl = "not found on port" if _LANG == "en" else "не обнаружен на порту"
    print(clr(f"\n  ⚠️  {name} {not_found_lbl} {port}", C.YELLOW))
    print(clr("\n" + t("  Что делаем?"), C.WHITE, C.BOLD))
    start_cmd = svc.get("start_cmd", [])
    if start_cmd:
        print(f"  {clr('1', C.CYAN, C.BOLD)}. {t('  Запустить ').strip()} {name}{t(' автоматически')}")
    print(f"  {clr('2', C.CYAN, C.BOLD)}. {t('  Запущу самостоятельно  (показать инструкцию)').strip()}")
    print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('  Отмена').strip()}")
    try: ch = input(clr("\n" + t("  Выбор: "), C.CYAN)).strip()
    except (KeyboardInterrupt, EOFError): print(); return False

    if ch == '1' and start_cmd:
        try:
            subprocess.Popen(start_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(clr(f"{t('  [*] Запускаю ')}{name}", C.GRAY), end='', flush=True)
            for _ in range(8):
                time.sleep(1); print(clr(".", C.GRAY), end='', flush=True)
                if check_service_running(svc):
                    started_lbl = "started" if _LANG == "en" else "запущен"
                    print(clr(f"\n  ✅ {name} {started_lbl}!", C.GREEN)); return True
            print(); print(clr(f"  ⚠️  {name}{t(' не ответил за 8 сек. Продолжаем.')}", C.YELLOW))
            return True
        except FileNotFoundError:
            not_in_path = "not found in PATH" if _LANG == "en" else "не найден в PATH"
            print(clr(f"\n  [!] {start_cmd[0]} {not_in_path}.", C.RED)); pause(); return False

    elif ch == '2':
        print(clr("\n" + t("  ── Инструкция ──────────────────────────────────────────────"), C.CYAN, C.BOLD))
        print(clr(f"\n{t('  1. Запусти ')}{name}{t(' в отдельном терминале.')}", C.WHITE))
        if name == "Ollama":
            print(clr("       ollama serve", C.YELLOW))
        print(clr("\n" + t("  2. Подключи клиент через прокси:"), C.WHITE))
        if name == "Ollama":
            print(clr(f"       export OLLAMA_HOST=http://localhost:{listen_port}", C.YELLOW))
            print(clr("       ollama run <модель>", C.YELLOW))
        else:
            print(clr(f"       Укажи в клиенте адрес: http://localhost:{listen_port}", C.YELLOW))
        print(clr("\n" + t("  ── Что такое Open WebUI? (необязательно) ───────────────────"), C.CYAN, C.BOLD))
        print(clr("\n" + t("  Open WebUI — веб-интерфейс для локальных AI, как ChatGPT, но офлайн."), C.WHITE))
        print(clr(t("  Открывается в браузере: история чатов, файлы, несколько моделей."), C.GRAY))
        print(clr(t("  Устанавливается отдельно. Если не используешь — пропусти."), C.GRAY))
        print(clr("\n" + t("  Если используешь Open WebUI:"), C.WHITE))
        print(clr(f"       Настройки → URL сервиса → http://localhost:{listen_port}", C.YELLOW))
        print(clr(t("  ────────────────────────────────────────────────────────────"), C.CYAN))
        pause(t("  Нажми Enter когда сервис будет запущен..."))
        if check_service_running(svc):
            found_lbl = "detected on port" if _LANG == "en" else "обнаружен на порту"
            print(clr(f"  ✅ {name} {found_lbl} {port}", C.GREEN)); return True
        still_lbl = "still not responding on port" if _LANG == "en" else "всё ещё не отвечает на порту"
        print(clr(f"  ⚠️  {name} {still_lbl} {port}", C.YELLOW))
        try:
            yn = input(clr(t("  Запустить прокси всё равно? [y/N]: "), C.CYAN)).strip().lower()
            return yn == 'y'
        except (KeyboardInterrupt, EOFError): return False

    return False

# ══════════════════════════════════════════════════════════════════════
#  ВЫБОР СЕРВИСА ДЛЯ ПРОКСИ
# ══════════════════════════════════════════════════════════════════════
def select_service_for_proxy():
    services = load_services()
    detected_ports = {s["port"] for s in _detected_services}
    print(clr("\n" + t("  Выбери AI-сервис:"), C.WHITE, C.BOLD))
    print()
    for i, svc in enumerate(services, 1):
        status = clr(t("✅ найден"), C.GREEN) if svc["port"] in detected_ports \
                 else clr(t("⬜ не найден"), C.GRAY)
        print(f"  {clr(str(i), C.CYAN, C.BOLD)}. {clr(svc['name'], C.WHITE):<14} "
              f":{svc['port']}  {status}")
    print(f"\n  {clr('m', C.CYAN, C.BOLD)}. {t('  Указать порты вручную').strip()}")
    print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('  Отмена').strip()}")
    try: ch = input(clr("\n" + t("  Выбор: "), C.CYAN)).strip()
    except (KeyboardInterrupt, EOFError): return None, None
    if ch == '0': return None, None
    if ch == 'm':
        try:
            lp = int(input(clr("  Порт прокси   [Enter=11435]: ", C.CYAN)).strip() or "11435")
            op = int(input(clr("  Порт сервиса  [Enter=11434]: ", C.CYAN)).strip() or "11434")
            return {"name":"Custom","host":"localhost","port":op,"proxy_port":lp,
                    "check_path":"/","api_paths":["/api/generate","/api/chat",
                    "/v1/chat/completions","/completion"],"format":"auto","start_cmd":[]}, lp
        except (ValueError, KeyboardInterrupt, EOFError): return None, None
    try:
        idx = int(ch) - 1
        if 0 <= idx < len(services):
            svc = services[idx]
            return svc, svc.get("proxy_port", svc["port"] + 1)
    except ValueError: pass
    return None, None

# ══════════════════════════════════════════════════════════════════════
#  ПАРСИНГ ОТВЕТА (универсальный)
# ══════════════════════════════════════════════════════════════════════
def extract_text(data: bytes, fmt: str) -> str:
    parts = []
    for line in data.decode('utf-8', errors='replace').splitlines():
        line = line.strip()
        if not line: continue
        try: obj = json.loads(line)
        except json.JSONDecodeError: continue
        text = ""
        if fmt == "ollama":
            text = obj.get('response', '')
            if not text:
                msg = obj.get('message') or {}
                text = msg.get('content', '') if isinstance(msg, dict) else ''
        elif fmt == "llamacpp":
            text = obj.get('content', '')
        elif fmt == "kobold":
            results = obj.get('results') or []
            text = results[0].get('text', '') if results else ''
        if not text:  # OpenAI / auto / fallback
            choices = obj.get('choices') or []
            if choices:
                delta = choices[0].get('delta') or choices[0].get('message') or {}
                text = delta.get('content', '')
        if not text:
            text = obj.get('response','') or obj.get('content','') or obj.get('text','')
        if text: parts.append(text)
    return ''.join(parts)

# ══════════════════════════════════════════════════════════════════════
#  ПРОКСИ-ИНСПЕКТОР (универсальный)
# ══════════════════════════════════════════════════════════════════════
def _proxy_log_path(svc_name: str) -> Path:
    """Возвращает путь к инкрементальному MD-логу прокси: LLM_logs/<сервис>/proxy_YYYY-MM-DD.md.
    Если сервис не в библиотеке — папка other/."""
    known_names = {s["name"] for s in load_services()}
    folder = svc_name if svc_name in known_names else "other"
    safe = re.sub(r'[^\w\-]', '_', folder)
    log_dir = DEFAULT_LOG_DIR / safe
    ensure_dir(log_dir)
    return log_dir / f"proxy_{datetime.now().strftime('%Y-%m-%d')}.md"

def monitor_proxy(svc: dict, listen_port: int):
    from http.server import HTTPServer, BaseHTTPRequestHandler
    _host     = svc.get("host", "localhost")
    _port     = svc["port"]
    _name     = svc.get("name", "AI")
    _api_paths= set(svc.get("api_paths", ["/api/generate","/api/chat",
                                           "/v1/chat/completions","/completion"]))
    _fmt      = svc.get("format", "auto")

    class _Proxy(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a): pass

        def _forward(self, method, body=b''):
            try:
                conn = http.client.HTTPConnection(_host, _port, timeout=300)
                hdrs = {k: v for k, v in self.headers.items()
                        if k.lower() not in ('host','content-length','transfer-encoding')}
                if body: hdrs['Content-Length'] = str(len(body))
                conn.request(method, self.path, body=body or None, headers=hdrs)
                resp = conn.getresponse(); data = resp.read(); conn.close()
                self.send_response(resp.status)
                skip = {'transfer-encoding','content-encoding','content-length'}
                for k, v in resp.getheaders():
                    if k.lower() not in skip: self.send_header(k, v)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers(); self.wfile.write(data); self.wfile.flush()
                if self.path in _api_paths: self._scan(data)
            except ConnectionRefusedError:
                print(clr(f"\n  [!] {_name} не запущен на порту {_port}", C.RED))
                self._err(502, f"{_name} unavailable")
            except Exception as e:
                print(clr(f"\n  [!] Прокси: {e}", C.RED)); self._err(502, str(e))

        def _err(self, code, msg):
            try: self.send_error(code, msg)
            except Exception: pass

        def _scan(self, data: bytes):
            full = extract_text(data, _fmt)
            if not full: return
            ts = datetime.now().strftime("%H:%M:%S")
            preview = full[:120].replace('\n', ' ')
            print(clr(f"\n  [{ts}] ← Ответ ({len(full)} симв.): "
                      f"{preview}{'...' if len(full)>120 else ''}", C.CYAN))
            scan_text(full, f"{_name} API", f"{_name} API {self.path}")

        def do_GET(self):    self._forward('GET')
        def do_DELETE(self): self._forward('DELETE')
        def do_HEAD(self):   self._forward('HEAD')
        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length) if length > 0 else b''
            if self.path in _api_paths and body:
                try:
                    req = json.loads(body)
                    prompt = req.get('prompt','')
                    if not prompt:
                        msgs = req.get('messages') or []
                        if msgs: prompt = msgs[-1].get('content','')
                    if prompt:
                        ts = datetime.now().strftime("%H:%M:%S")
                        req_lbl = "Request" if _LANG == "en" else "Запрос"
                        print(clr(f"  [{ts}] → {req_lbl}: {str(prompt)[:100]}", C.GRAY))
                except Exception: pass
            self._forward('POST', body)

    try:
        server = HTTPServer(('localhost', listen_port), _Proxy)
    except OSError as e:
        if e.errno in (98, 48, 10048):
            print(clr(f"\n  [!] Порт {listen_port} уже занят.", C.RED))
            # Попытка узнать какой процесс занимает порт
            _info = ""
            for _cmd in [
                ["ss", "-tlnp", f"sport = :{listen_port}"],
                ["lsof", "-i", f"TCP:{listen_port}", "-sTCP:LISTEN", "-n", "-P"],
            ]:
                try:
                    _r = subprocess.run(_cmd, capture_output=True, text=True, timeout=3)
                    if _r.returncode == 0:
                        _lines = [l for l in _r.stdout.splitlines()
                                  if str(listen_port) in l and l.strip()]
                        if _lines:
                            _info = _lines[0].strip()[:90]
                            break
                except Exception:
                    pass
            if _info:
                print(clr(f"  Занят: {_info}", C.GRAY))
            print(clr(f"\n  Что делать:", C.YELLOW))
            print(clr(f"  • В меню Прокси выбери 'm. Настроить вручную' и укажи другой порт прокси.", C.YELLOW))
            print(clr(f"  • Или останови процесс, который занимает порт {listen_port}.", C.YELLOW))
        else:
            print(clr(f"\n  [!] {e}", C.RED))
        return

    # ── инкрементальный MD-лог сессии (3-шаговая защита) ────────────
    global _proxy_inc_log
    _session_start = datetime.now()
    _pre_log = _proxy_log_path(_name)
    _is_new_log = not _pre_log.exists()
    if _is_new_log:
        _log_header = (
            f"# LLM Filter Scanner — Прокси-лог\n\n"
            f"**Сервис:** {_name}  \n"
            f"**Начало:** {_session_start.strftime('%Y-%m-%d %H:%M:%S')}  \n"
            f"**Версия:** {VERSION}  \n\n"
            f"---\n\n"
        )
        if create_md_file(_pre_log, _log_header, "лога прокси"):
            print(clr(f"  📝 Создан лог: {_pre_log}", C.GRAY))
        else:
            print(clr(f"  ⚠️  Лог не создан — данные только в памяти.", C.YELLOW))
    else:
        # Файл уже есть (продолжение за сегодня) — дописываем разделитель сессии
        print(clr(f"\n  📝 Лог: {_pre_log}  (продолжение за сегодня)", C.GRAY))
        try:
            with open(_pre_log, 'a', encoding='utf-8') as _f:
                _f.write(
                    f"## ── Новая сессия: {_session_start.strftime('%H:%M:%S')} ──\n\n"
                )
        except Exception: pass
    _proxy_inc_log = _pre_log if _pre_log.exists() else None

    print(clr(f"\n  [*] Прокси-инспектор запущен  (Ctrl+C — стоп)\n", C.GREEN, C.BOLD))
    print(clr(f"      Сервис : {_name}  localhost:{_port}", C.CYAN))
    print(clr(f"      Прокси : http://localhost:{listen_port}", C.CYAN))
    print()
    print(clr(t("  ⚙️  Как подключить клиент:"), C.WHITE, C.BOLD))
    if svc.get("name") == "Ollama":
        print(clr(f"      export OLLAMA_HOST=http://localhost:{listen_port}", C.YELLOW))
        print(clr( "      ollama run <модель>", C.YELLOW))
    else:
        print(clr(f"      Укажи в клиенте: http://localhost:{listen_port}", C.YELLOW))
    print(clr(f"      Open WebUI: настройки → URL сервиса → http://localhost:{listen_port}", C.YELLOW))
    print()
    print(clr(t("  Все ответы сканируются в реальном времени.\n"), C.GRAY))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(clr("\n\n" + t("  [*] Прокси остановлен."), C.GREEN))
        server.shutdown()

    # ── финализация инкрементального лога ───────────────────────────
    _session_end = datetime.now()
    if _proxy_inc_log and _proxy_inc_log.exists() and alert_log:
        cnt = {}
        for a in alert_log: cnt[a['severity']] = cnt.get(a['severity'], 0) + 1
        rows = '\n'.join(
            f"| {SEV.get(sk,(C.WHITE,'?'))[1]} {sk} | {cnt.get(sk,0)} |"
            for sk in ["CRITICAL","HIGH","MEDIUM","INFO"])
        footer = (
            f"{t('## Итоги сессии')}\n\n"
            f"{t('**Конец:**')} {_session_end.strftime('%Y-%m-%d %H:%M:%S')}  \n"
            f"{t('**Всего алертов:**')} {len(alert_log)}  \n\n"
            f"{t('| Уровень | Количество |')}\n"
            f"{t('|---------|------------|')}\n"
            f"{rows}\n"
        )
        try:
            with open(_proxy_inc_log, 'a', encoding='utf-8') as _f:
                _f.write(footer)
            log_updated_lbl = "  📝 Log updated with summary:" if _LANG == "en" else "  📝 Лог дополнен итогами:"
            print(clr(f"{log_updated_lbl} {_proxy_inc_log}", C.GRAY))
        except Exception: pass
    _proxy_inc_log = None  # сбрасываем — вне сессии инкрементальная запись не нужна

    # Сохраняем сводный отчёт внутри функции — защита от второго Ctrl+C в main()
    try:
        show_and_save_report()
    except (KeyboardInterrupt, Exception):
        if alert_log:
            _rp = DEFAULT_LOG_DIR / f"llm_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            try:
                ensure_dir(DEFAULT_LOG_DIR)
                _rp.write_text('\n'.join([f"- {a['severity']}: {a['type']} | {a['detail'][:100]}"
                                          for a in alert_log]), encoding='utf-8')
                print(clr(f"\n  💾 Аварийное сохранение: {_rp}", C.YELLOW))
            except Exception: pass

# ══════════════════════════════════════════════════════════════════════
#  ЖИВОЙ МОНИТОРИНГ — journalctl
# ══════════════════════════════════════════════════════════════════════
def monitor_journalctl(service="ollama"):
    print(clr(f"\n  [*] journalctl -u {service} -f  (Ctrl+C — стоп)\n", C.GREEN, C.BOLD))
    print(clr("  ⚠️  journalctl показывает системные метаданные, а не текст ответов.", C.YELLOW))
    print(clr("      Для перехвата ответов используй Прокси-инспектор.\n", C.YELLOW))
    proc = None
    while True:
        try:
            proc = subprocess.Popen(
                ["journalctl","-u",service,"-f","--no-pager","-o","short"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace', bufsize=1)
            print(clr(f"  [✓] PID {proc.pid}", C.GREEN))
            for raw in proc.stdout:
                line = raw.rstrip('\r\n')
                if not line.strip(): continue
                check_stopwords(line, "journalctl")
                scan_line(line, f"journalctl/{service}", "journalctl")
                ts = datetime.now().strftime("%H:%M:%S")
                print(clr(f"  [{ts}] {line[:110]}{'...' if len(line)>110 else ''}", C.GRAY))
        except KeyboardInterrupt:
            print(clr("\n\n  [*] Мониторинг остановлен.", C.GREEN)); break
        except FileNotFoundError:
            print(clr("\n  [!] journalctl не найден — используй режим лог-файла.", C.RED)); break
        except Exception as e:
            print(clr(f"\n  [!] {e}. Переподключение через 3 сек...", C.RED)); time.sleep(3)
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except: proc.kill()

# ══════════════════════════════════════════════════════════════════════
#  ЖИВОЙ МОНИТОРИНГ — лог-файл
# ══════════════════════════════════════════════════════════════════════
def monitor_logfile(log_path):
    log = resolve_path(log_path)
    print(clr(f"\n  [*] Мониторинг: {log}  (Ctrl+C — стоп)\n", C.GREEN, C.BOLD))
    if not ensure_dir(log.parent):
        print(clr("  [!] Мониторинг отменён — папка недоступна.", C.RED)); return
    if not log.exists():
        try:
            log.write_text(f"[System] Log created by LLM Filter Scanner v{VERSION}\n",
                           encoding='utf-8')
            print(clr(f"  [✓] Создан файл лога: {log}", C.GREEN))
        except Exception as e:
            print(clr(f"  [!] Не удалось создать файл лога: {e}", C.RED)); return
    while True:
        try:
            with open(log, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(0, 2); print(clr("  [✓] Жду новых строк...", C.GREEN))
                while True:
                    line = f.readline()
                    if not line: time.sleep(0.1); continue
                    line = line.rstrip('\r\n')
                    if not line.strip(): continue
                    check_stopwords(line, "лог-файл")
                    scan_line(line, str(log), "лог-файл")
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(clr(f"  [{ts}] {line[:110]}{'...' if len(line)>110 else ''}", C.GRAY))
        except KeyboardInterrupt:
            print(clr("\n\n  [*] Мониторинг остановлен.", C.GREEN)); break
        except Exception as e:
            print(clr(f"\n  [!] {e}. Переподключение через 2 сек...", C.RED)); time.sleep(2)

# ══════════════════════════════════════════════════════════════════════
#  РЕДАКТОР СТОП-СЛОВ
# ══════════════════════════════════════════════════════════════════════
def edit_stopwords():
    global STOP_WORDS
    while True:
        subprocess.run(['clear'])
        STOP_WORDS = load_stopwords()
        file_exists = STOPWORDS_FILE.exists()
        print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN, C.BOLD))
        print(clr(f"║      Стоп-слова — LLM Filter Scanner v{VERSION}         ║", C.CYAN, C.BOLD))
        print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN, C.BOLD))
        if file_exists:
            print(clr(f"  Файл : {STOPWORDS_FILE}", C.GRAY))
            print(clr(f"  Слов : {len(STOP_WORDS)}", C.YELLOW, C.BOLD))
        else:
            print(clr(f"\n  ⚠️  Файл не найден: {STOPWORDS_FILE}", C.RED, C.BOLD))
            print(clr("  Стоп-слова не активны.", C.YELLOW))
        print(clr("\n  ──────────────────────────────────────────────────", C.GRAY))
        if not file_exists:
            print(f"  {clr('c', C.CYAN, C.BOLD)}. Создать файл (3 шага)")
        else:
            print(f"  {clr('v', C.CYAN, C.BOLD)}. Просмотреть список")
            print(f"  {clr('a', C.CYAN, C.BOLD)}. Добавить слово/фразу")
            print(f"  {clr('d', C.CYAN, C.BOLD)}. Удалить по номеру")
            print(f"  {clr('r', C.CYAN, C.BOLD)}. Восстановить слова по умолчанию  "
                  + clr("← только отсутствующие", C.GRAY))
            print(f"  {clr('e', C.CYAN, C.BOLD)}. Открыть в редакторе  "
                  + clr(f"← {os.environ.get('EDITOR','nano')}", C.GRAY))
        print(f"  {clr('q', C.CYAN, C.BOLD)}. Назад")
        prompt = "[c/q]" if not file_exists else "[v/a/d/r/e/q]"
        try: ch = input(clr(f"\n  Действие {prompt}: ", C.CYAN)).strip().lower()
        except (KeyboardInterrupt, EOFError): break

        if ch == 'c' and not file_exists:
            if create_md_file(STOPWORDS_FILE, SW_HEADER + DEFAULT_STOPWORDS, "стоп-слов"):
                STOP_WORDS = load_stopwords()
            pause()
        elif ch == 'v' and file_exists:
            subprocess.run(['clear'])
            print(clr(f"\n  Стоп-слова ({len(STOP_WORDS)})  —  {STOPWORDS_FILE}\n", C.CYAN, C.BOLD))
            for i, w in enumerate(STOP_WORDS, 1): print(f"  {clr(f'{i:>3}.', C.GRAY)} {w}")
            pause()
        elif ch == 'a' and file_exists:
            try:
                new = input(clr("  Новая фраза: ", C.CYAN)).strip().lower()
                if new and new not in STOP_WORDS:
                    STOP_WORDS.append(new); save_stopwords(STOP_WORDS)
                elif new in STOP_WORDS: print(clr("  Уже есть в списке.", C.YELLOW))
            except (KeyboardInterrupt, EOFError): pass
            pause()
        elif ch == 'd' and file_exists:
            try:
                idx = int(input(clr("  Номер для удаления: ", C.CYAN)).strip()) - 1
                if 0 <= idx < len(STOP_WORDS):
                    removed = STOP_WORDS.pop(idx)
                    if save_stopwords(STOP_WORDS): print(clr(f"  Удалено: '{removed}'", C.GRAY))
                else: print(clr("  Неверный номер.", C.RED))
            except (ValueError, KeyboardInterrupt, EOFError): pass
            pause()
        elif ch == 'r' and file_exists:
            n = restore_default_stopwords()
            if n == 0: print(clr("  Все слова по умолчанию уже есть в списке.", C.GRAY))
            else: STOP_WORDS = load_stopwords(); print(clr(f"  ✅ Добавлено {n} слов.", C.GREEN))
            pause()
        elif ch == 'e' and file_exists:
            subprocess.run([os.environ.get('EDITOR','nano'), str(STOPWORDS_FILE)])
            STOP_WORDS = load_stopwords()
            print(clr(f"\n  Перезагружено. Слов: {len(STOP_WORDS)}", C.GRAY)); pause()
        elif ch == 'q': break

# ══════════════════════════════════════════════════════════════════════
#  РЕДАКТОР БЕЛОГО СПИСКА
# ══════════════════════════════════════════════════════════════════════
def edit_whitelist():
    global WHITELIST
    while True:
        subprocess.run(['clear'])
        WHITELIST = load_whitelist()
        file_exists = WHITELIST_FILE.exists()
        print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN, C.BOLD))
        print(clr(f"║      Белый список — LLM Filter Scanner v{VERSION}       ║", C.CYAN, C.BOLD))
        print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN, C.BOLD))
        print(clr("  Записи из этого списка НЕ вызывают алертов.", C.GRAY))
        print(clr("  Поддержка sudo — имеется", C.GRAY))
        if file_exists:
            print(clr(f"\n  Файл    : {WHITELIST_FILE}", C.GRAY))
            print(clr(f"  Записей : {len(WHITELIST)}", C.YELLOW, C.BOLD))
        else:
            print(clr(f"\n  ⚠️  Файл не найден: {WHITELIST_FILE}", C.YELLOW))
            print(clr("  Все алерты активны.", C.GRAY))
        print(clr("\n  ──────────────────────────────────────────────────", C.GRAY))
        if not file_exists:
            print(f"  {clr('c', C.CYAN, C.BOLD)}. Создать файл (3 шага)")
        else:
            print(f"  {clr('v', C.CYAN, C.BOLD)}. Просмотреть список")
            print(f"  {clr('a', C.CYAN, C.BOLD)}. Добавить запись  "
                  + clr("← URL, домен, IP или часть строки", C.GRAY))
            print(f"  {clr('d', C.CYAN, C.BOLD)}. Удалить по номеру")
            print(f"  {clr('e', C.CYAN, C.BOLD)}. Открыть в редакторе  "
                  + clr(f"← {os.environ.get('EDITOR','nano')}", C.GRAY))
        print(f"  {clr('q', C.CYAN, C.BOLD)}. Назад")
        prompt = "[c/q]" if not file_exists else "[v/a/d/e/q]"
        try: ch = input(clr(f"\n  Действие {prompt}: ", C.CYAN)).strip().lower()
        except (KeyboardInterrupt, EOFError): break

        if ch == 'c' and not file_exists:
            if create_md_file(WHITELIST_FILE, WL_HEADER, "белого списка"):
                WHITELIST = load_whitelist()
            pause()
        elif ch == 'v' and file_exists:
            subprocess.run(['clear'])
            print(clr(f"\n  Белый список ({len(WHITELIST)})  —  {WHITELIST_FILE}\n", C.CYAN, C.BOLD))
            if WHITELIST:
                for i, w in enumerate(WHITELIST, 1): print(f"  {clr(f'{i:>3}.', C.GRAY)} {w}")
            else:
                print(clr("  Список пуст.", C.YELLOW))
            pause()
        elif ch == 'a' and file_exists:
            try:
                new = input(clr("  Новая запись: ", C.CYAN)).strip().lower()
                if new and new not in WHITELIST:
                    WHITELIST.append(new)
                    if _file_write(WHITELIST_FILE, WL_HEADER + '\n'.join(WHITELIST) + '\n'):
                        print(clr(f"  ✅ Добавлено: '{new}'", C.GREEN))
                elif new in WHITELIST: print(clr("  Уже есть в списке.", C.YELLOW))
            except (KeyboardInterrupt, EOFError): pass
            pause()
        elif ch == 'd' and file_exists:
            try:
                idx = int(input(clr("  Номер для удаления: ", C.CYAN)).strip()) - 1
                if 0 <= idx < len(WHITELIST):
                    removed = WHITELIST.pop(idx)
                    if _file_write(WHITELIST_FILE, WL_HEADER + '\n'.join(WHITELIST) + '\n'):
                        print(clr(f"  Удалено: '{removed}'", C.GRAY))
                else: print(clr("  Неверный номер.", C.RED))
            except (ValueError, KeyboardInterrupt, EOFError): pass
            pause()
        elif ch == 'e' and file_exists:
            subprocess.run([os.environ.get('EDITOR','nano'), str(WHITELIST_FILE)])
            WHITELIST = load_whitelist()
            print(clr(f"\n  Перезагружено. Записей: {len(WHITELIST)}", C.GRAY)); pause()
        elif ch == 'q': break

# ══════════════════════════════════════════════════════════════════════
#  ПРОФИЛИ
# ══════════════════════════════════════════════════════════════════════
def load_profiles():
    if PROFILES_FILE.exists():
        try: return json.loads(PROFILES_FILE.read_text(encoding='utf-8'))
        except Exception: pass
    return {"active": "default", "profiles": [{"name": "default"}]}

def save_profiles(data):
    ensure_dir(LLMFSC_DIR)
    content = json.dumps(data, ensure_ascii=False, indent=2)
    if not PROFILES_FILE.exists():
        # 3-шаговое создание + chown → читается без sudo в дальнейшем
        if not _file_touch(PROFILES_FILE): return
        _file_chmod(PROFILES_FILE)
        _file_write(PROFILES_FILE, content)
    else:
        if not _file_write_safe(PROFILES_FILE, content):
            print(clr("  ❌ Профиль не сохранён.", C.RED))

def profiles_menu():
    global STOP_WORDS, WHITELIST
    while True:
        subprocess.run(['clear'])
        data     = load_profiles()
        active   = data.get("active", "default")
        profiles = data.get("profiles", [])
        print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN, C.BOLD))
        print(clr(f"║         Профили — LLM Filter Scanner v{VERSION}          ║", C.CYAN, C.BOLD))
        print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN, C.BOLD))
        print(clr("  Поддержка sudo — имеется", C.GRAY))
        print(clr(f"\n  Активный: {clr(active, C.GREEN, C.BOLD)}", C.WHITE))
        print()
        print(f"  {clr('1', C.CYAN, C.BOLD)}. ✏️  Стоп-слова    "
              + clr(f"← {len(STOP_WORDS)} слов", C.MAGENTA))
        print(f"  {clr('2', C.CYAN, C.BOLD)}. 🚫  Белый список  "
              + clr(f"← {len(WHITELIST)} записей", C.GRAY))
        print(clr("\n  ──────────────────────────────────────────────────", C.GRAY))
        print(clr("  Создание новых профилей — бессмысленно (удалить потом)", C.GRAY))
        print(clr("  3. 💾  Сохранить профиль", C.GRAY))
        print(clr("  4. 📂  Загрузить профиль", C.GRAY))
        if len(profiles) > 1:
            print(clr("  5. 🗑️  Удалить профиль", C.GRAY))
        print(clr("\n  ──────────────────────────────────────────────────", C.GRAY))
        print(f"  {clr('0', C.CYAN, C.BOLD)}. Назад")
        try: ch = input(clr("\n" + t("  Действие: "), C.CYAN)).strip()
        except (KeyboardInterrupt, EOFError): break

        if ch == '1':
            edit_stopwords(); STOP_WORDS = load_stopwords()
        elif ch == '2':
            edit_whitelist(); WHITELIST = load_whitelist()
        elif ch == '3':
            try: name = input(clr(f"  Имя профиля [{active}]: ", C.CYAN)).strip() or active
            except (KeyboardInterrupt, EOFError): continue
            found = next((p for p in profiles if p["name"] == name), None)
            entry = {"name": name, "stopwords": str(STOPWORDS_FILE),
                     "whitelist": str(WHITELIST_FILE)}
            if found: found.update(entry)
            else: profiles.append(entry)
            data["active"] = name; data["profiles"] = profiles
            save_profiles(data)
            print(clr(f"  ✅ Профиль '{name}' сохранён.", C.GREEN)); pause()
        elif ch == '4':
            if not profiles:
                print(clr("  Нет сохранённых профилей.", C.YELLOW)); pause(); continue
            print(clr("\n  Доступные профили:", C.WHITE))
            for i, p in enumerate(profiles, 1):
                marker = clr(" ← активный", C.GREEN) if p["name"] == active else ""
                print(f"  {clr(str(i), C.CYAN, C.BOLD)}. {p['name']}{marker}")
            try:
                idx = int(input(clr("\n  Номер: ", C.CYAN)).strip()) - 1
                if 0 <= idx < len(profiles):
                    data["active"] = profiles[idx]["name"]
                    save_profiles(data)
                    print(clr(f"  ✅ Активный: {profiles[idx]['name']}", C.GREEN))
            except (ValueError, KeyboardInterrupt, EOFError): pass
            pause()
        elif ch == '5' and len(profiles) > 1:
            print(clr("\n  Удалить профиль:", C.WHITE))
            for i, p in enumerate(profiles, 1):
                if p["name"] != "default":
                    print(f"  {clr(str(i), C.CYAN, C.BOLD)}. {p['name']}")
            try:
                idx = int(input(clr("\n  Номер: ", C.CYAN)).strip()) - 1
                if 0 <= idx < len(profiles) and profiles[idx]["name"] != "default":
                    removed = profiles.pop(idx)
                    if data["active"] == removed["name"]: data["active"] = "default"
                    data["profiles"] = profiles; save_profiles(data)
                    print(clr(f"  Удалён: '{removed['name']}'", C.GRAY))
                else: print(clr("  Нельзя удалить.", C.YELLOW))
            except (ValueError, KeyboardInterrupt, EOFError): pass
            pause()
        elif ch == '0': break

# ══════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: МОНИТОРИНГ ЛОГОВ
# ══════════════════════════════════════════════════════════════════════
def logs_menu():
    while True:
        subprocess.run(['clear'])
        print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN, C.BOLD))
        print(clr(f"║    {t('Мониторинг логов')} — LLM Filter Scanner v{VERSION}      ║", C.CYAN, C.BOLD))
        print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN, C.BOLD))
        print()
        print(f"  {clr('1', C.CYAN, C.BOLD)}. {t('🔴  Journalctl')}")
        print(clr(t("       Мониторинг системного журнала сервиса в реальном времени."), C.GRAY))
        print(clr(t("       Сценарий: сервис запущен, нужно поймать подозрительные"), C.GRAY))
        print(clr(t("       системные вызовы, сетевые подключения в метаданных."), C.GRAY))
        print()
        print(f"  {clr('2', C.CYAN, C.BOLD)}. {t('📄  Лог-файл')}")
        print(clr(t("       Мониторинг произвольного .log файла (tail -f)."), C.GRAY))
        print(clr(t("       Сценарий: сервис пишет лог на диск, хочешь видеть"), C.GRAY))
        print(clr(t("       алерты по мере появления новых строк."), C.GRAY))
        print()
        print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('Назад')}")
        try: ch = input(clr(t("  Выбор [0-2]: "), C.CYAN)).strip()
        except (KeyboardInterrupt, EOFError): break

        if ch == '1':
            subprocess.run(['clear'])
            print(clr(t("  Journalctl — мониторинг системного журнала\n"), C.WHITE, C.BOLD))
            print(clr(t("  Читает journalctl -u <сервис> -f и сканирует каждую строку."), C.GRAY))
            print(clr(t("  Ctrl+C — остановить.\n"), C.GRAY))
            # Список сервисов с маркером обнаружения
            all_svcs = load_services()
            det_ports = {s["port"] for s in _detected_services}
            print(clr(t("  Сервисы:"), C.WHITE, C.BOLD))
            for i, s in enumerate(all_svcs, 1):
                mark = clr("✅", C.GREEN) if s["port"] in det_ports else clr("⬜", C.GRAY)
                jname = s["name"].lower().replace(" ", "")
                print(f"  {clr(str(i), C.CYAN, C.BOLD)}. {mark} {s['name']}  "
                      f"{clr(f'(journalctl -u {jname})', C.GRAY)}")
            print(f"  {clr('n', C.CYAN, C.BOLD)}. {t('  Другой сервис').strip()}")
            print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('  Отмена').strip()}")
            try:
                jch = input(clr(f"\n  Выбор [1-{len(all_svcs)}/n/0]: ", C.CYAN)).strip().lower()
            except (KeyboardInterrupt, EOFError):
                jch = None
            if jch is None or jch == '0':
                pause(); continue
            if jch.isdigit():
                idx = int(jch) - 1
                svc = all_svcs[idx]["name"].lower().replace(" ", "") if 0 <= idx < len(all_svcs) else "ollama"
            elif jch and jch != 'n':
                svc = jch
            else:
                try: svc = input(clr("  Имя сервиса [Enter=ollama]: ", C.CYAN)).strip() or "ollama"
                except (KeyboardInterrupt, EOFError): continue
            monitor_journalctl(svc); show_and_save_report(); pause()
        elif ch == '2':
            subprocess.run(['clear'])
            print(clr(t("  Лог-файл — мониторинг файла в реальном времени\n"), C.WHITE, C.BOLD))
            print(clr(t("  Читает файл по мере его роста (как tail -f)."), C.GRAY))
            print(clr(t("  В другом терминале можно перенаправить journalctl:"), C.GRAY))
            print(clr("    journalctl -u <сервис> -f >> <путь.log>", C.YELLOW))
            lp = ask_logfile_with_hints()
            if lp: monitor_logfile(lp); show_and_save_report()
            pause()
        elif ch == '0': break

# ══════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: БИБЛИОТЕКА СЕРВИСОВ
# ══════════════════════════════════════════════════════════════════════
def services_menu():
    while True:
        subprocess.run(['clear'])
        services = load_services()
        detected_ports = {s["port"] for s in _detected_services}
        print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN, C.BOLD))
        print(clr(f"║    {t('Библиотека сервисов')} — LLM Filter Scanner v{VERSION}   ║", C.CYAN, C.BOLD))
        print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN, C.BOLD))
        print(clr(f"\n  Файл: {SERVICES_FILE}", C.GRAY))
        print(clr(f"  Сервисов: {len(services)}\n", C.WHITE))
        for svc in services:
            status = clr("✅", C.GREEN) if svc["port"] in detected_ports else clr("⬜", C.GRAY)
            proxy_p = svc.get("proxy_port", svc["port"]+1)
            print(f"  {status} {clr(svc['name'], C.WHITE):<14} "
                  f":{svc['port']}  "
                  + clr(f"прокси:{proxy_p}  формат:{svc.get('format','?')}", C.GRAY))
        print(clr("\n  ──────────────────────────────────────────────────", C.GRAY))
        if SERVICES_UPDATE_URL:
            print(clr(f"  GitHub URL: {SERVICES_UPDATE_URL}", C.GRAY))
        else:
            print(clr("  GitHub URL: не настроен", C.YELLOW))
        print(f"  {clr('u', C.CYAN, C.BOLD)}. ⬇️  Обновить с GitHub")
        print(f"  {clr('c', C.CYAN, C.BOLD)}. 🔗  Настроить URL обновления")
        if not SERVICES_FILE.exists():
            print(f"  {clr('s', C.CYAN, C.BOLD)}. 💾  Сохранить текущую библиотеку в файл")
        print(f"  {clr('0', C.CYAN, C.BOLD)}. Назад")
        try: ch = input(clr("\n" + t("  Действие: "), C.CYAN)).strip().lower()
        except (KeyboardInterrupt, EOFError): break
        if ch == 'u': update_services_from_github()
        elif ch == 'c':
            current = clr(SERVICES_UPDATE_URL, C.CYAN) if SERVICES_UPDATE_URL else clr("не задан", C.YELLOW)
            print(clr(f"\n  Текущий URL: ", C.GRAY) + current)
            print(clr("  Пример: https://raw.githubusercontent.com/user/repo/main/services.json", C.GRAY))
            print(clr("  Enter без ввода — отмена.", C.GRAY))
            try: new_url = input(clr("  Новый URL (0 — отмена): ", C.CYAN)).strip()
            except (KeyboardInterrupt, EOFError): new_url = ""
            if new_url and new_url != '0':
                save_update_url(new_url)
                print(clr(f"  ✅ URL сохранён.", C.GREEN))
            pause()
        elif ch == 's' and not SERVICES_FILE.exists():
            save_services(services)
            print(clr(f"  ✅ Сохранено: {SERVICES_FILE}", C.GREEN)); pause()
        elif ch == '0': break

# ══════════════════════════════════════════════════════════════════════
#  ОТЧЁТ (MD)
# ══════════════════════════════════════════════════════════════════════
def show_and_save_report():
    global _session_report_saved
    if not alert_log:
        print(clr("\n  ✅ Алертов в сессии не было.", C.GREEN)); return

    print(clr(f"\n  Алертов: {len(alert_log)}\n", C.YELLOW, C.BOLD))
    cnt = {}
    for a in alert_log: cnt[a['severity']] = cnt.get(a['severity'], 0) + 1
    for sev, n in sorted(cnt.items()):
        col, icon = SEV.get(sev, (C.WHITE, "?"))
        print(f"    {icon} {clr(sev, col)}: {n}")

    ensure_dir(DEFAULT_LOG_DIR)
    rp = DEFAULT_LOG_DIR / f"llm_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

    lines = [
        t("# LLM Filter Scanner — Отчёт сессии"), "",
        f"{t('**Дата:**')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"{t('**Версия:**')} {VERSION}  ",
        f"{t('**Всего алертов:**')} {len(alert_log)}", "",
        t("## Статистика"), "",
        t("| Уровень | Количество |"),
        t("|---------|------------|"),
    ]
    for sk in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        icon = SEV.get(sk, (C.WHITE, "?"))[1]
        lines.append(f"| {icon} {sk} | {cnt.get(sk, 0)} |")
    lines += ["", t("## Алерты"), ""]
    for a in alert_log:
        icon = SEV.get(a['severity'], (C.WHITE, "?"))[1]
        lines += [
            f"### {icon} {a['severity']} — {a['type']}", "",
            f"- {t('**Время:**')} {a['time']}",
            f"- {t('**Источник:**')} {a['source']}",
            f"- {t('**Место:**')} {a['location']}",
            f"- {t('**Детали:**')} `{a['detail'][:300]}`", "",
        ]
    if _file_write_safe(rp, '\n'.join(lines)):
        _session_report_saved = True
        saved_lbl = "  💾 Report saved:" if _LANG == "en" else "  💾 Отчёт сохранён:"
        print(clr(f"\n{saved_lbl} {rp}", C.CYAN))
    else:
        print(clr(f"\n  [!] Не удалось сохранить отчёт.", C.RED))

# ══════════════════════════════════════════════════════════════════════
#  КАТАЛОГ ФАЙЛОВ ДАННЫХ
# ══════════════════════════════════════════════════════════════════════
def show_file_catalog():
    """Дерево ~/Documents/llmfs/ с размерами файлов."""
    subprocess.run(['clear'])
    print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN, C.BOLD))
    print(clr(f"║   Каталог данных — LLM Filter Scanner v{VERSION}         ║", C.CYAN, C.BOLD))
    print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN, C.BOLD))
    print()
    if not LLMFSC_DIR.exists():
        print(clr(f"  Папка данных не существует: {LLMFSC_DIR}", C.YELLOW))
        pause(); return

    print(clr(f"  {LLMFSC_DIR}/", C.WHITE, C.BOLD))
    print()

    def _tree(path: Path, prefix: str = "", depth: int = 0):
        if depth > 4:
            return
        try:
            entries = sorted(path.iterdir(), key=lambda e: (e.is_file(), e.name.lower()))
        except PermissionError:
            print(f"  {prefix}└── {clr('[нет доступа]', C.RED)}")
            return
        for i, entry in enumerate(entries):
            is_last = (i == len(entries) - 1)
            conn = "└── " if is_last else "├── "
            ext  = "    " if is_last else "│   "
            if entry.is_dir():
                print(f"  {prefix}{conn}{clr(entry.name + '/', C.CYAN)}")
                _tree(entry, prefix + ext, depth + 1)
            else:
                try:
                    sz = entry.stat().st_size
                    sz_str = f"{sz // 1024}K" if sz >= 1024 else f"{sz}B"
                except Exception:
                    sz_str = "?"
                print(f"  {prefix}{conn}{entry.name}  {clr(sz_str, C.GRAY)}")

    _tree(LLMFSC_DIR)
    print()
    pause()

# ══════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: ОТЧЁТЫ И ДАННЫЕ
# ══════════════════════════════════════════════════════════════════════
def _parse_delete_spec(spec: str, max_n: int) -> list | None:
    """Парсит спецификацию удаления. Возвращает список 0-based индексов или None при ошибке.
    Форматы: 'all' → все; '5-20' → диапазон; '1 3 5 6' → список; '5' → один.
    """
    spec = spec.strip()
    if spec == 'all':
        return list(range(max_n))
    if re.fullmatch(r'\d+-\d+', spec):
        a, b = map(int, spec.split('-'))
        idxs = [i - 1 for i in range(a, b + 1) if 1 <= i <= max_n]
        return idxs if idxs else []
    parts = spec.split()
    if all(p.isdigit() for p in parts):
        idxs = []
        for p in parts:
            i = int(p) - 1
            if 0 <= i < max_n and i not in idxs:
                idxs.append(i)
        return idxs
    return None

def _list_reports() -> list:
    """Список .md отчётов из DEFAULT_LOG_DIR и подпапок, новейшие первыми."""
    if not DEFAULT_LOG_DIR.exists():
        return []
    files = sorted(DEFAULT_LOG_DIR.rglob("*.md"),
                   key=lambda f: f.stat().st_mtime, reverse=True)
    return files

def _view_report(f: Path):
    """Вывод отчёта в терминал постранично."""
    subprocess.run(['clear'])
    print(clr(f"\n  📄 {f}\n", C.CYAN, C.BOLD))
    try:
        text = f.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        print(clr(f"  [!] Ошибка чтения: {e}", C.RED)); pause(); return

    lines = text.splitlines()
    PAGE = 40
    total = len(lines)
    offset = 0
    while offset < total:
        chunk = lines[offset:offset + PAGE]
        for ln in chunk: print(f"  {ln}")
        offset += PAGE
        if offset < total:
            try:
                cmd = input(clr(f"\n  [{offset}/{total}] Enter — далее, q — выход: ", C.GRAY)).strip().lower()
                if cmd == 'q': break
            except (KeyboardInterrupt, EOFError): break
    pause()

def reports_menu():
    while True:
        subprocess.run(['clear'])
        print(clr("╔══════════════════════════════════════════════════════╗", C.CYAN, C.BOLD))
        print(clr(f"║   {t('Отчеты и данные')} — LLM Filter Scanner v{VERSION}        ║", C.CYAN, C.BOLD))
        print(clr("╚══════════════════════════════════════════════════════╝", C.CYAN, C.BOLD))
        print(clr(t("  Поддержка sudo — имеется"), C.GRAY))
        fldr = "  Folder: " if _LANG == "en" else "  Папка: "
        print(clr(f"\n{fldr}{DEFAULT_LOG_DIR}\n", C.GRAY))

        files = _list_reports()
        if not files:
            print(clr(t("  Отчётов пока нет."), C.YELLOW))
        else:
            for i, f in enumerate(files, 1):
                try:
                    mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                    size  = f.stat().st_size
                    sz    = f"{size//1024}K" if size >= 1024 else f"{size}B"
                except Exception:
                    mtime, sz = "?", "?"
                # показываем относительный путь внутри DEFAULT_LOG_DIR
                try:    rel = f.relative_to(DEFAULT_LOG_DIR)
                except: rel = f.name
                print(f"  {clr(f'{i:>3}.', C.GRAY)} {clr(str(rel), C.WHITE)}"
                      f"  {clr(mtime, C.GRAY)}  {clr(sz, C.GRAY)}")

        print(clr("\n  ──────────────────────────────────────────────────", C.GRAY))
        if alert_log:
            al_hint = ("alerts" if _LANG=="en" else "алертов")
            if _session_report_saved:
                print(f"  {clr('s', C.CYAN, C.BOLD)}. {t('💾  Сохранить отчёт текущей сессии')}  "
                      + clr(f"← {len(alert_log)} {al_hint}  ✅ " + ("saved" if _LANG=="en" else "уже сохранён"), C.GRAY))
            else:
                print(f"  {clr('s', C.CYAN, C.BOLD)}. {t('💾  Сохранить отчёт текущей сессии')}  "
                      + clr(f"← {len(alert_log)} {al_hint}", C.YELLOW))
        if files:
            print(f"  {clr('<N>', C.CYAN, C.BOLD)}. {t('Просмотреть отчёт №N')}")
            print(f"  {clr('d<N>', C.CYAN, C.BOLD)}. {t('Удалить №N')}   "
                  + clr(t("d1 3 5  d5-20  dall"), C.GRAY))
        print(clr("  ──────────────────────────────────────────────────", C.GRAY))
        print(f"  {clr('c', C.CYAN, C.BOLD)}. {t('📁  Каталог файлов данных')}  "
              + clr(f"← {LLMFSC_DIR}", C.GRAY))
        print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('Назад')}")

        try: ch = input(clr("\n" + t("  Действие: "), C.CYAN)).strip().lower()
        except (KeyboardInterrupt, EOFError): break

        if ch == '0':
            break
        elif ch == 'c':
            show_file_catalog()
        elif ch == 's' and alert_log:
            if _session_report_saved:
                print(clr("\n" + t("  ℹ️  Отчёт этой сессии уже сохранён."), C.YELLOW))
                print(clr(t("  Повторное сохранение создаст дубликат."), C.GRAY))
                try: confirm = input(clr(t("  Всё равно сохранить ещё раз? [y/N]: "), C.CYAN)).strip().lower()
                except (KeyboardInterrupt, EOFError): confirm = ""
                if confirm == 'y':
                    show_and_save_report()
            else:
                show_and_save_report()
            pause()
        elif ch.startswith('d') and len(ch) > 1:
            spec = ch[1:].strip()
            idxs = _parse_delete_spec(spec, len(files))
            if idxs is None:
                print(clr(t("  Неверный формат. Примеры: d3  d1 3 5  d5-20  dall"), C.RED)); pause()
            elif not idxs:
                print(clr(t("  Нет файлов для удаления."), C.YELLOW)); pause()
            else:
                to_del = [files[i] for i in idxs]
                ndel = "file(s)" if _LANG=="en" else "файл(ов)"
                will = "Will delete" if _LANG=="en" else "Будет удалено"
                print(clr(f"\n  {will} {len(to_del)} {ndel}:", C.YELLOW))
                for f in to_del:
                    print(clr(f"    • {f.name}", C.WHITE))
                del_q = "Delete" if _LANG=="en" else "Удалить"
                try: yn = input(clr(f"\n  {del_q} {len(to_del)} {ndel}? [y/N]: ", C.CYAN)).strip().lower()
                except (KeyboardInterrupt, EOFError): yn = ""
                if yn == 'y':
                    ok = err = 0
                    for f in to_del:
                        try:
                            f.unlink(); ok += 1
                        except PermissionError:
                            print(clr(f"  [!] Нет прав: {f.name}", C.RED)); err += 1
                        except Exception as e:
                            print(clr(f"  [!] {f.name}: {e}", C.RED)); err += 1
                    print(clr(f"\n  ✅ Удалено: {ok}", C.GREEN)
                          + (clr(f"   ❌ Ошибок: {err}", C.RED) if err else ""))
                else:
                    print(clr(t("  Отмена."), C.GRAY))
                pause()
        else:
            try:
                idx = int(ch) - 1
                if 0 <= idx < len(files):
                    _view_report(files[idx])
                else:
                    print(clr(t("  Неверный номер."), C.RED)); pause()
            except ValueError:
                print(clr(t("  Неверный ввод."), C.RED)); pause()

# ══════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════
def hdr():
    subprocess.run(['clear']); print()
    W  = 70
    L1 = f"       LLM FILTER SCANNER v{VERSION}  —  {t('Анализатор AI-сервисов')}"
    L2 = f"  {t('Статика • Прокси-инспектор • Мониторинг • Профили • Библиотека')}"
    print(clr("╔" + "═"*W + "╗", C.CYAN, C.BOLD))
    print(clr("║" + L1.ljust(W) + "║", C.CYAN, C.BOLD))
    print(clr("║" + L2.ljust(W) + "║", C.CYAN, C.BOLD))
    print(clr("╚" + "═"*W + "╝", C.CYAN, C.BOLD))
    sw_lbl = "stop words" if _LANG == "en" else "стоп-слов"
    sw_miss = "stop words not loaded" if _LANG == "en" else "стоп-слова не загружены"
    sw  = clr(f"{len(STOP_WORDS)} {sw_lbl}", C.MAGENTA) if STOP_WORDS \
          else clr(sw_miss, C.YELLOW)
    wl  = clr(f"  {len(WHITELIST)} whitelist", C.GRAY) if WHITELIST else ""
    al_lbl = "Alerts: " if _LANG == "en" else "Алертов: "
    if _detection_done and _detected_services:
        det = clr("  " + t("Найдено: ") + ", ".join(s["name"] for s in _detected_services), C.GRAY)
    elif _detection_done:
        det = clr("  " + t("Сервисов не обнаружено"), C.GRAY)
    else:
        det = clr("  " + t("Поиск сервисов..."), C.GRAY)
    print(clr(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}    "
              f"{al_lbl}{len(alert_log)}    {sw}{wl}", C.GRAY))
    print(det); print()

def ask(prompt, default=""):
    try:
        v = input(clr(f"  {prompt}", C.CYAN)).strip().strip('"\'')
        return v or default
    except (KeyboardInterrupt, EOFError): return default

def main():
    global STOP_WORDS, WHITELIST
    load_lang()
    start_detection()
    while True:
        hdr()
        print(clr(t("  Выбери режим:") + "\n", C.WHITE, C.BOLD))
        print(f"  {clr('1', C.CYAN, C.BOLD)}. 📁  {t('Сканирование файлов и папок')}  "
              + clr(t("← файлы, папки, .gguf, текст"), C.GRAY))
        print(f"  {clr('2', C.CYAN, C.BOLD)}. 🤖  {t('Сканирование AI-моделей')}     "
              + clr(t("← автопоиск Ollama, LM Studio…"), C.GRAY))
        print(f"  {clr('3', C.CYAN, C.BOLD)}. 🔌  Прокси-инспектор              "
              + clr(t("← перехват ответов в реальном времени"), C.GREEN))
        print(clr("  ─────────────────────────────────────────────────────", C.GRAY))
        print(f"  {clr('4', C.CYAN, C.BOLD)}. 📋  {t('Мониторинг логов ›')}            "
              + clr(t("← journalctl, лог-файлы"), C.GRAY))
        sw_hint = clr(f"← {len(STOP_WORDS)} " + ("stop words" if _LANG=="en" else "стоп-слов")
                      + f"  {len(WHITELIST)} whitelist", C.GRAY)
        print(f"  {clr('5', C.CYAN, C.BOLD)}. 👤  {t('Профили ›')}                     " + sw_hint)
        print(f"  {clr('6', C.CYAN, C.BOLD)}. 📡  {t('Библиотека сервисов ›')}         "
              + clr(f"← {len(load_services())} " + ("services" if _LANG=="en" else "сервисов"), C.GRAY))
        print(clr("  ─────────────────────────────────────────────────────", C.GRAY))
        print(f"  {clr('7', C.CYAN, C.BOLD)}. 📊  {t('Отчеты и данные ›')}             "
              + clr(f"← {DEFAULT_LOG_DIR}", C.GRAY))
        print(f"  {clr('L', C.CYAN, C.BOLD)}. {t('🌐  Language / Язык')}              "
              + clr(f"← {_LANG}", C.GRAY))
        print(f"  {clr('0', C.CYAN, C.BOLD)}. {t('🚪  Выход')}")

        ch = ask(t("Ваш выбор [0-7]: "))

        try:
            if ch == '1':
                hdr()
                p = ask_folder_with_history("Файл или папка для сканирования")
                if p: static_scan(p); show_and_save_report()
                pause()

            elif ch == '2':
                hdr()
                print(clr("  " + t("Сканирование AI-моделей"), C.WHITE, C.BOLD))
                print(clr(t("  Ищет подозрительные паттерны в файлах моделей (GGUF и др.)\n"), C.GRAY))
                p = ai_models_menu()
                if p: static_scan(p)
                pause()

            elif ch == '3':
                hdr()
                print(clr(t("  Прокси-инспектор — перехват ответов AI-сервиса"), C.WHITE, C.BOLD))
                print(clr(t("  Все ответы сканируются в реальном времени.\n"), C.GRAY))
                svc, listen_port = select_service_for_proxy()
                if svc is None: pause(); continue
                if not ask_service_start(svc, listen_port): pause(); continue
                monitor_proxy(svc, listen_port)  # отчёт сохраняется внутри
                pause()

            elif ch == '4':
                logs_menu()

            elif ch == '5':
                profiles_menu()
                STOP_WORDS = load_stopwords()
                WHITELIST  = load_whitelist()

            elif ch == '6':
                services_menu()

            elif ch == '7':
                reports_menu()

            elif ch in ('l', 'L'):
                lang_menu()

            elif ch == '0':
                if alert_log: show_and_save_report()
                bye = "  Goodbye!\n" if _LANG == "en" else "  До свидания!\n"
                print(clr(f"\n{bye}", C.GREEN)); sys.exit(0)

        except KeyboardInterrupt:
            print(clr("\n\n" + t("  [*] Прервано, возврат в меню..."), C.YELLOW)); pause()
        except Exception as e:
            print(clr(f"\n  ❌ Ошибка: {e}", C.RED))
            import traceback; traceback.print_exc()
            pause(t("  Нажмите Enter для возврата в меню..."))

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt:
        print(clr("\n\n" + t("  Прервано. Сохраняю..."), C.YELLOW))
        show_and_save_report(); sys.exit(0)
