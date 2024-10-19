#ifndef CRYPTOSYSTEM_H
#define CRYPTOSYSTEM_H

// Подключение необходимых библиотек
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <ctime>
#include <windows.h>
#include <stdexcept>

// Использование пространства имен std
using namespace std;

// Объявление функций для работы с файлами
string FileInput(const string &filename); // Функция чтения из файла
string FileOutput(const string &filename, const string &str); // Функция записи в файл

// Функция для ввода и проверки сообщения или ключа
void input_and_check(string &message, const string &choice_cipher, const string &message_or_key);

// Функция для шифрования и дешифрования
void Enc_and_Desc(const string &choice_cipher);


// Объявление переменной пароля
extern const string passwd;

#endif // CRYPTOSYSTEM_H
