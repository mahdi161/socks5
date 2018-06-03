#!/usr/bin/python
# -*- coding:utf-8 -*-
from bs4 import BeautifulSoup
import requests
import socket
import struct
# подключение к сайту с прокси
url = "http://www.gatherproxy.com/ru/sockslist"
reqheaders = {
    'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) \ '
                  'AppleWebKit/537.36 (KHTML, like Gecko) \ '
                  'Chrome/62.0.3202.94 Safari/537.36',
}
session = requests.Session()
resp = session.get(url, data={}, headers=reqheaders)
# получение кода ответа
if resp.status_code != 200:
    print("Ошибка при чтении страницы. Код ответа HTTP - " + resp.status_code)
# парсинг кода
bsObj = BeautifulSoup(resp.text, "html.parser")
# очистка всех тегов script
# [el.extract() for el in bsObj('script')]
parsecode = bsObj.findAll("td")


# функция проверки прокси на работоспособность
# Возвращает True, если прокси рабочая, при любых ошибках возвращает False
def checkproxy(ip, port):
    try:
        port = int(port)
    except ValueError as msg:
        print('Некорректный порт')
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            s.sendall(struct.pack(
                '!BBB',
                0x05,  # Номер версии SOCKS
                0x01,  # Количество поддерживаемых методов аутентификации
                0x00,  # Номера методов аутентификации, 1 байт для каждого метода
                ))
            recv = s.recv(1024)
            # ответ сервера
            # 1 байт - Номер версии SOCKS (должен быть 0x05 для этой версии)
            # 1 байт - Выбранный метод аутентификации или 0xFF, если нет приемлемого метода
            if recv == b'\x05\x00':
                return True
            return False
    except socket.gaierror as msg:
        print("Некорректный адрес")
        return False
    except socket.timeout as msg:
        print("Таймаут подключения")
        return False


iplist = []
ports = []
# заполняем списки ip-адреов и портов
i = 0
for item in parsecode:
    tempObj = BeautifulSoup(str(item), "html.parser")
    data = tempObj.get_text(" ")
    if "document.write" in data:
        if i % 2 == 0:
            iplist.append(data.split("'")[1])
            i += 1
        else:
            ports.append(data.split("'")[1])
            i += 1

itemsToCheck = list(zip(iplist, ports))

for i in itemsToCheck:
    if checkproxy(i[0], i[1]):
        print("Рабочий SOCKS5 прокси: {0}:{1}".format(i[0], i[1]))
        break
