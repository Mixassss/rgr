#include <sstream>

#include "Cryptosystem.h"

bool isLetter(char stroka) { // Проверка, является ли символ буквой
    return (stroka >= 'A' && stroka <= 'Z') || (stroka >= 'a' && stroka <= 'z');
}

char toUpper(char stroka) { // Преобразование символа в верхний регистр
    if (stroka >= 'a' && stroka <= 'z') {
        return stroka - ('a' - 'A'); // Преобразуем в верхний регистр
    }
    return stroka; // Если уже в верхнем регистре или не буква, возвращаем без изменений
}

vector<char> checkinputa1z26(string message) { // Функция для проверки ввода для шифра A1Z26
    vector<char> invalidChars;
    for (char stroka : message) {
        if (!(isLetter(stroka) || stroka == ' ')) {
            invalidChars.push_back(stroka);
        }
    }
    return invalidChars;
}

string generateCipherAlphabet(string key) { // Функция для генерации шифрующего алфавита на основе ключевого слова
    string cipherAlphabet; 
    bool lettersUsed[26] = { false };

    for (char& stroka : key) { // Преобразуем ключ в верхний регистр и удаляем повторяющиеся буквы
        if (isLetter(stroka)) {
            stroka = toUpper(stroka);
            if (!lettersUsed[stroka - 'A']) {
                cipherAlphabet += stroka;
                lettersUsed[stroka - 'A'] = true;
            }
        }
    }

    for (char stroka = 'A'; stroka <= 'Z'; stroka++) { // Добавляем оставшиеся буквы алфавита
        if (!lettersUsed[stroka - 'A']) {
            cipherAlphabet += stroka;
            lettersUsed[stroka - 'A'] = true;
        }
    }

    return cipherAlphabet;
}

string myToString(int number) { // Функция для преобразования числа в строку
    string result;
    if (number == 0) return "0";
    while (number > 0) {
        result = char((number % 10) + '0') + result;
        number /= 10;
    }
    return result;
}

string a1z26Encryption(string message, string key) { // Функция шифрования сообщения с помощью шифра A1Z26 и ключевого слова
    string cipherAlphabet = generateCipherAlphabet(key); // Генерируем шифрующий алфавит на основе ключевого слова

    string encryptedMessage = "";

    for (char stroka : message) { // Преобразуем сообщение
        if (isLetter(stroka)) {
            stroka = toUpper(stroka);
            size_t pos = cipherAlphabet.find(stroka); // Находим позицию буквы в шифрующем алфавите
            if (pos < cipherAlphabet.length()) { // Проверяем, найдена ли буква
                encryptedMessage += myToString(pos + 1) + "-"; // Добавляем номер буквы (от 1 до 26)
            }
        } else if (stroka == ' ') { // Проверяем на пробел
            encryptedMessage += "/-"; // Заменяем пробел на символ '/'
        }
    }

    if (!encryptedMessage.empty() && encryptedMessage.back() == '-') { // Удаляем последний символ '-'
        encryptedMessage.pop_back();
    }

    return encryptedMessage;
}

string a1z26Decryption(string message, string key) { // Функция расшифровки сообщения с помощью шифра A1Z26 и ключевого слова
    string cipherAlphabet = generateCipherAlphabet(key); // Генерируем шифрующий алфавит на основе ключевого слова

    string decryptedMessage = "";
    string token = "";
    istringstream tokenStream(message);

    while (getline(tokenStream, token, '-')) {
        if (token == "/") {
            decryptedMessage += " ";
        } else {
            try {
                int num = stoi(token);
                if (num >= 1 && num <= 26) {
                    decryptedMessage += cipherAlphabet[num - 1];
                } else {
                    decryptedMessage += '?'; // Неизвестный номер
                }
            } catch (invalid_argument&) {
                decryptedMessage += '?'; // Некорректный токен
            }
        }
    }

    return decryptedMessage;
}
