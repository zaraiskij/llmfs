# llmfs
🔍 AI service analyzer: scan responses, proxy inspector, log monitoring. Ollama, LM Studio, LocalAI. Python stdlib only, no dependencies.

# LLM Filter Scanner

Консольный анализатор AI-сервисов. Сканирует ответы на стоп-слова,
телеметрию, подозрительные паттерны. Поддержка Ollama, LM Studio,
LocalAI, Jan, KoboldCpp, TabbyML, llama.cpp.

---

# LLM Filter Scanner (English)

Terminal-based AI service analyzer. Scans responses for stop words,
telemetry, suspicious patterns. Supports Ollama, LM Studio, LocalAI,
Jan, KoboldCpp, TabbyML, llama.cpp.

## Установка / Install

### Arch Linux (yay)
yay -S llmfs

### Все системы / All systems
Требуется Python 3.8+ / Requires Python 3.8+
wget https://raw.githubusercontent.com/zaraiskij/llmfs/main/llmfs.py
chmod +x llmfs.py
python3 llmfs.py

## Использование / Usage

python3 llmfs.py
python3 llmfs.py --lang en

## Меню / Menu

1. Сканирование файлов и папок / File & folder scan
2. Сканирование AI-моделей / AI model scan  
3. Прокси-инспектор / Proxy inspector
4. Мониторинг логов / Log monitoring
5. Профили (стоп-слова, белый список) / Profiles
6. Библиотека сервисов / Service library
7. Отчеты и данные / Reports & data

## Требования / Requirements

- Python 3.8+
- Linux / macOS
- Без внешних зависимостей / No external dependencies
