#include <map>

#include "Cryptosystem.h"

// Функция для проверки ввода для шифра Бэкона
vector<char> checkinputbacon(const string& message) {
    vector<char> invalidChars;
    for (char c : message) {
        // Допустимые символы: латинские буквы A-Z и a-z
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= 'А' && c <= 'Я') || (c >= 'а' && c <= 'я') || 
              c == ' ')) {
            invalidChars.push_back(c);
        }
    }
    return invalidChars;
}

// Функция шифрования сообщения с помощью шифра Бэкона
string baconEncryption(const string& message) {
    // Создаем таблицу соответствия букв и кодов Бэкона
    map<char, string> baconMap = {
        {'A', "AAAAA"}, {'B', "AAAAB"}, {'C', "AAABA"}, {'D', "AAABB"},
        {'E', "AABAA"}, {'F', "AABAB"}, {'G', "AABBA"}, {'H', "AABBB"},
        {'I', "ABAAA"}, {'J', "ABAAB"}, {'K', "ABABA"}, {'L', "ABABB"},
        {'M', "ABBAA"}, {'N', "ABBAB"}, {'O', "ABBBA"}, {'P', "ABBBB"},
        {'Q', "BAAAA"}, {'R', "BAAAB"}, {'S', "BAABA"}, {'T', "BAABB"},
        {'U', "BABAA"}, {'V', "BABAB"}, {'W', "BABBA"}, {'X', "BABBB"},
        {'Y', "BBAAA"}, {'Z', "BBAAB"},
        // Русские буквы
        {'А', "AAAAA"}, {'Б', "AAAAB"}, {'В', "AAABA"}, {'Г', "AAABB"},
        {'Д', "AABAA"}, {'Е', "AABAB"}, {'Ё', "AABBA"}, {'Ж', "AABBB"},
        {'З', "ABAAA"}, {'И', "ABAAB"}, {'Й', "ABABA"}, {'К', "ABABB"},
        {'Л', "ABBAA"}, {'М', "ABBAB"}, {'Н', "ABBBA"}, {'О', "ABBBB"},
        {'П', "BAAAA"}, {'Р', "BAAAB"}, {'С', "BAABA"}, {'Т', "BAABB"},
        {'У', "BABAA"}, {'Ф', "BABAB"}, {'Х', "BABBA"}, {'Ц', "BABBB"},
        {'Ч', "BBAAA"}, {'Ш', "BBAAB"}, {'Щ', "BBAAC"}, {'Ъ', "BBAAD"},
        {'Ы', "BBAAE"}, {'Ь', "BBAAF"}, {'Э', "BBAAG"}, {'Ю', "BBAAH"},
        {'Я', "BBAAI"}
    };

    string encryptedMessage;

    for (char c : message) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= 'А' && c <= 'Я') || (c >= 'а' && c <= 'я')) {
            // Преобразуем в верхний регистр
            if (c >= 'a' && c <= 'z') {
                c = c - ('a' - 'A');  // Преобразование в верхний регистр
            }
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
        {"BBAAA", 'Y'}, {"BBAAB", 'Z'},
        // Русские буквы
        {"AAAAA", 'А'}, {"AAAAB", 'Б'}, {"AAABA", 'В'}, {"AAABB", 'Г'},
        {"AABAA", 'Д'}, {"AABAB", 'Е'}, {"AABBA", 'Ё'}, {"AABBB", 'Ж'},
        {"ABAAA", 'З'}, {"ABAAB", 'И'}, {"ABABA", 'Й'}, {"ABABB", 'К'},
        {"ABBAA", 'Л'}, {"ABBAB", 'М'}, {"ABBBA", 'Н'}, {"ABBBB", 'О'},
        {"BAAAA", 'П'}, {"BAAAB", 'Р'}, {"BAABA", 'С'}, {"BAABB", 'Т'},
        {"BABAA", 'У'}, {"BABAB", 'Ф'}, {"BABBA", 'Х'}, {"BABBB", 'Ц'},
        {"BBAAA", 'Ч'}, {"BBAAB", 'Ш'}, {"BBAAC", 'Щ'}, {"BBAAD", 'Ъ'},
        {"BBAAE", 'Ы'}, {"BBAAF", 'Ь'}, {"BBAAG", 'Э'}, {"BBAAH", 'Ю'},
        {"BBAAI", 'Я'}
    };

    string decryptedMessage;

    // Удаляем пробелы и недопустимые символы из сообщения
    string filteredMessage;
    for (char c : message) {
        if (c == 'A' || c == 'B' || c == 'a' || c == 'b') {
            filteredMessage += c;
        }
    }

    // Проверяем, что длина сообщения кратна 5
    if (filteredMessage.length() % 5 != 0) {
        return "Error: Invalid encrypted message length.";
    }

    // Разбиваем сообщение на блоки по 5 символов и расшифровываем
    for (size_t i = 0; i < filteredMessage.length(); i += 5) {
        string code = filteredMessage.substr(i, 5);
        if (baconMap.find(code) != baconMap.end()) {
            decryptedMessage += baconMap[code];
        } else {
            decryptedMessage += '?'; // Неизвестный код
        }
    }

    return decryptedMessage;
}
