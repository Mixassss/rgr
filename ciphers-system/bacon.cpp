#include <map>

#include "Cryptosystem.h"

// Функция для проверки ввода для шифра Бэкона
vector<char> checkinputbacon(const string& message) {
    vector<char> invalidChars;
    for (char c : message) {
        // Допустимые символы: латинские буквы A-Z и a-z
        if (!isalpha(c) && !isspace(c)) {
            invalidChars.push_back(c);
        }
    }
    return invalidChars;
}

// Функция шифрования сообщения с помощью шифра Бэкона
string baconEncryption(const string& message) {
    // Создаем таблицу соответствия букв и кодов Бэкона
    pmr::map<char, string> baconMap = {
        {'A', "AAAAA"}, {'B', "AAAAB"}, {'C', "AAABA"}, {'D', "AAABB"},
        {'E', "AABAA"}, {'F', "AABAB"}, {'G', "AABBA"}, {'H', "AABBB"},
        {'I', "ABAAA"}, {'J', "ABAAB"}, {'K', "ABABA"}, {'L', "ABABB"},
        {'M', "ABBAA"}, {'N', "ABBAB"}, {'O', "ABBBA"}, {'P', "ABBBB"},
        {'Q', "BAAAA"}, {'R', "BAAAB"}, {'S', "BAABA"}, {'T', "BAABB"},
        {'U', "BABAA"}, {'V', "BABAB"}, {'W', "BABBA"}, {'X', "BABBB"},
        {'Y', "BBAAA"}, {'Z', "BBAAB"}
    };

    string encryptedMessage;

    // Преобразуем сообщение в верхний регистр и удаляем недопустимые символы
    for (char c : message) {
        if (isalpha(c)) {
            c = toupper(c);
            encryptedMessage += baconMap[c];
        }
    }

    return encryptedMessage;
}

// Функция расшифровки сообщения с помощью шифра Бэкона
string baconDecryption(const string& message) {
    // Создаем обратную таблицу соответствия кодов Бэкона и букв
    map<string, char> baconMap = {
        {"AAAAA", 'A'}, {"AAAAB", 'B'}, {"AAABA", 'C'}, {"AAABB", 'D'},
        {"AABAA", 'E'}, {"AABAB", 'F'}, {"AABBA", 'G'}, {"AABBB", 'H'},
        {"ABAAA", 'I'}, {"ABAAB", 'J'}, {"ABABA", 'K'}, {"ABABB", 'L'},
        {"ABBAA", 'M'}, {"ABBAB", 'N'}, {"ABBBA", 'O'}, {"ABBBB", 'P'},
        {"BAAAA", 'Q'}, {"BAAAB", 'R'}, {"BAABA", 'S'}, {"BAABB", 'T'},
        {"BABAA", 'U'}, {"BABAB", 'V'}, {"BABBA", 'W'}, {"BABBB", 'X'},
        {"BBAAA", 'Y'}, {"BBAAB", 'Z'}
    };

    string decryptedMessage;

    // Удаляем пробелы и недопустимые символы из сообщения
    string filteredMessage;
    for (char c : message) {
        if (c == 'A' || c == 'B' || c == 'a' || c == 'b') {
            filteredMessage += toupper(c);
        }
    }

    // Проверяем, что длина сообщения кратна 5
    if (filteredMessage.length() % 5 != 0) {
        return "Error: Invalid encrypted message length.";
    }

    // Разбиваем сообщение на блоки по 5 символов и расшифровываем
    for (size_t i = 0; i < filteredMessage.length(); i += 5) {
        if (string code = filteredMessage.substr(i, 5); baconMap.find(code) != baconMap.end()) {
            decryptedMessage += baconMap[code];
        } else {
            decryptedMessage += '?'; // Неизвестный код
        }
    }

    return decryptedMessage;
}
