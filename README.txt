
Проект - интерактивный сайт «Помощник к ЕГЭ»

Как запустить (Windows):

1) Распакуйте содержимое архива в папку, например на Рабочий стол:
   C:\Users\<ВашеИмя>\Desktop\ege_project

2) Откройте Командную строку (CMD) и перейдите в папку проекта:
   cd /d "%USERPROFILE%\Desktop\ege_project"

3) Создайте виртуальное окружение и активируйте его:
   py -3 -m venv venv
   venv\Scripts\activate.bat

4) Установите зависимости:
   pip install --upgrade pip
   pip install -r requirements.txt

5) Запустите сервер:
   python app.py

6) Откройте в браузере:
   http://localhost:5000
