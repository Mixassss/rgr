#include <sstream>

#include "Cryptosystem.h"

// Функция для проверки ввода для шифра A1Z26
vector<char> checkinputa1z26(string message) {
    vector<char> invalidChars;
    for (char c : message) {
        // Допустимые символы: латинские буквы A-Z и a-z, пробелы
        if (!isalpha(c) && !isspace(c)) {
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
        if (isalpha(c)) {
            c = toupper(c);
            if (!lettersUsed[c - 'A']) {
                cipherAlphabet += c;
                lettersUsed[c - 'A'] = true;
            }
        }
    }

    // Добавляем оставшиеся буквы алфавита
    for (char c = 'A'; c <= 'Z'; c++) {
        if (!lettersUsed[c - 'A']) {
            cipherAlphabet += c;
            lettersUsed[c - 'A'] = true;
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
        if (isalpha(c)) {
            c = toupper(c);
            // Находим позицию буквы в шифрующем алфавите
            size_t pos = cipherAlphabet.find(c);
            if (pos != string::npos) {
                // Добавляем номер буквы (от 1 до 26)
                encryptedMessage += to_string(pos + 1) + "-";
            }
        } else if (isspace(c)) {
            // Заменяем пробел на символ '/'
            encryptedMessage += "/-";
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
