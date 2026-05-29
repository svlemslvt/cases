
## 2. `.gitignore` – исключаем служебные и временные файлы

```gitignore
# Зависимости
node_modules/

# Логи
*.log
npm-debug.log*

# Файлы окружения (если добавите .env)
.env
.env.local
.env.*.local

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
