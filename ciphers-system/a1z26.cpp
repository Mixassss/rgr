#include <sstream>

#include "Cryptosystem.h"

// Функция для проверки ввода для шифра A1Z26
vector<char> checkinputa1z26(string message) {
    vector<char> invalidChars;
    for (char c : message) {
        // Допустимые символы: латинские буквы A-Z и a-z, пробелы
        if (!( (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ')) {
            invalidChars.push_back(c);
        }
    }
    return invalidChars;
}

// Функция для генерации шифрующего алфавита на основе ключевого слова
string generateCipherAlphabet(string key) {
    string cipherAlphabet;
    bool lettersUsed[26] = { false };

    // Преобразуем ключ в верхний регистр и удаляем повторяющиеся буквы
    for (char& c : key) {
        if (c >= 'A' && c <= 'Z') {
        } else if (c >= 'a' && c <= 'z') { // Буква уже в верхнем регистре
            c = c - ('a' - 'A'); // Преобразуем строчную букву в заглавную
        } else {
            continue; // Игнорируем неалфавитные символы
        }
        if (!lettersUsed[c - 'A']) {
            cipherAlphabet += c;
            lettersUsed[c - 'A'] = true;
        }
    }

    // Добавляем оставшиеся буквы алфавита
    for (char c = 'A'; c <= 'Z'; c++) {
        if (!lettersUsed[c - 'A']) {
            cipherAlphabet += c;
        }
    }

    return cipherAlphabet;
}

// Функция шифрования сообщения с помощью шифра A1Z26 и ключевого слова
string a1z26Encryption(string message, string key) {
    // Генерируем шифрующий алфавит на основе ключевого слова
    string cipherAlphabet = generateCipherAlphabet(key);
    string encryptedMessage = "";

    // Преобразуем сообщение
    for (char c : message) {
        if (c >= 'A' && c <= 'Z') {
            // Буква уже в верхнем регистре
        } else if (c >= 'a' && c <= 'z') {
            // Преобразуем строчную букву в заглавную
            c = c - ('a' - 'A');
        } else if (c == ' ') {
            encryptedMessage += "/-";
            continue;
        } else {
            continue; // Пропускаем неалфавитные символы
        }
        
        // Находим позицию буквы в шифрующем алфавите
        size_t pos = cipherAlphabet.find(c);
        if (pos != string::npos) {
            encryptedMessage += to_string(pos + 1) + "-"; // Добавляем номер буквы (от 1 до 26)
        }
    }

    // Удаляем последний символ '-'
    if (!encryptedMessage.empty() && encryptedMessage.back() == '-') {
        encryptedMessage.pop_back();
    }

    return encryptedMessage;
}

// Функция расшифровки сообщения с помощью шифра A1Z26 и ключевого слова
string a1z26Decryption(string message, string key) {
    // Генерируем шифрующий алфавит на основе ключевого слова
    string cipherAlphabet = generateCipherAlphabet(key);
    string decryptedMessage = "";

    string token;
    istringstream tokenStream(message);

    while (getline(tokenStream, token, '-')) {
        if (token == "/") {
        decryptedMessage += " ";
        } else {
        bool isNumber = true; // Проверяем, является ли токен числом
        for (char c : token) {
            if (c < '0' || c > '9') { // Проверяем, является ли символ цифрой
                isNumber = false;
                break;
            }
        }

        if (isNumber) {
            int num = stoi(token);
            if (num >= 1 && num <= 26) {
                decryptedMessage += cipherAlphabet[num - 1];
            } else {
                decryptedMessage += '?'; // Неизвестный номер
            }
            } else {
                decryptedMessage += '?'; // Некорректный токен
            }
        }
    }
    return decryptedMessage;
}
