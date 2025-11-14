
Проект - интерактивный сайт «Помощник к ЕГЭ»

Как запустить (Windows):

1) Откройте командную строку (CMD) и перейдите в папку проекта:
   cd /d "%USERPROFILE%\Desktop\ege_project"

2) Создайте виртуальное окружение и активируйте его:
   py -3 -m venv venv
   venv\Scripts\activate.bat

3) Установите зависимости:
   pip install --upgrade pip
   pip install -r requirements.txt

4) Запустите сервер:
   python app.py

5) Откройте в браузере:
   http://localhost:5000
