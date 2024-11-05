#include <map>

#include "Cryptosystem.h"

// Функция для проверки ввода для шифра Бэкона
vector<char> checkinputbacon(const string& message) {
    vector<char> invalidChars;
    for (char c : message) {
        // Допустимые символы: латинские и кириллические буквы, кириллические буквы, пробел
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= 'А' && c <= 'Я') || (c >= 'а' && c <= 'я') || 
               c == ' ')) {
            invalidChars.push_back(c);
        }
    }
    return invalidChars;
}

string baconEncryption(string& message) {
    map<char, string> baconMap = {
        // English
        {'A', "AAAAA"}, {'B', "AAAAB"}, {'C', "AAABA"}, {'D', "AAABB"},
        {'E', "AABAA"}, {'F', "AABAB"}, {'G', "AABBA"}, {'H', "AABBB"},
        {'I', "ABAAA"}, {'J', "ABAAB"}, {'K', "ABABA"}, {'L', "ABABB"},
        {'M', "ABBAA"}, {'N', "ABBAB"}, {'O', "ABBBA"}, {'P', "ABBBB"},
        {'Q', "BAAAA"}, {'R', "BAAAB"}, {'S', "BAABA"}, {'T', "BAABB"},
        {'U', "BABAA"}, {'V', "BABAB"}, {'W', "BABBA"}, {'X', "BABBB"},
        {'Y', "BBAAA"}, {'Z', "BBAAB"},
        {'a', "aaaaa"}, {'b', "aaaab"}, {'c', "aaaba"}, {'d', "aaabb"},
        {'e', "aabaa"}, {'f', "aabab"}, {'g', "aabba"}, {'h', "aabbb"},
        {'i', "abaaa"}, {'j', "abaab"}, {'k', "ababa"}, {'l', "ababb"},
        {'m', "abbaaa"}, {'n', "abbab"}, {'o', "abbba"}, {'p', "abbbb"},
        {'q', "baaaa"}, {'r', "baaab"}, {'s', "baaba"}, {'t', "baabb"},
        {'u', "babaa"}, {'v', "babab"}, {'w', "babba"}, {'x', "babbb"},
        {'y', "bbaaa"}, {'z', "bbaab"},
        
        {'А', "ААААА"}, {'Б', "ААААB",}, {'В', "АААBА"}, {'Г', "АААBB"},
        {'Д', "ААBАА"}, {'Е', "ААBАB"}, {'Ё', "ААBАB"}, {'Ж', "ААBBА"},
        {'З', "ААBBB"}, {'И', "АBААА"}, {'Й', "АBААB"}, {'К', "АBАBА"},
        {'Л', "АBАBB"}, {'М', "АBBАА"}, {'Н', "АBBАB"}, {'О', "АBBBА"},
        {'П', "АBBBB"}, {'Р', "BАААА"}, {'С', "BАААB"}, {'Т', "BААBА"},
        {'У', "BААBB"}, {'Ф', "BАBАА"}, {'Х', "BАBАB"}, {'Ц', "BАBBА"},
        {'Ч', "BАBBB"}, {'Ш', "BBААА"}, {'Щ', "BBААB"}, {'Ъ', "BBАBА"},
        {'Ы', "BBАBB"}, {'Ь', "BBBАА"}, {'Э', "BBBАB"}, {'Ю', "BBBBА"},
        {'Я', "BBBBB"},
        {'а', "ааааа"}, {'б', "ааааb",}, {'в', "аааbа"}, {'г', "аааbb"},
        {'д', "ааbаа"}, {'е', "ааbаb"}, {'ё', "ааbаb"}, {'ж', "ааbbа"},
        {'з', "ааbbb"}, {'и', "аbааа"}, {'й', "аbааb"}, {'к', "аbаbа"},
        {'л', "аbаbb"}, {'м', "аbbаа"}, {'н', "аbbаb"}, {'о', "аbbbа"},
        {'п', "аbbbb"}, {'р', "bаааа"}, {'с', "bаааb"}, {'т', "bааbа"},
        {'у', "bааbb"}, {'ф', "bаbаа"}, {'х', "bаbаb"}, {'ц', "bаbbа"},
        {'ч', "bаbbb"}, {'ш', "bbааа"}, {'щ', "bbааb"}, {'ъ', "bbаbа"},
        {'ы', "bbаbb"}, {'ь', "bbbаа"}, {'э', "bbbаb"}, {'ю', "bbbbа"},
        {'я', "bbbbb"}
    };

    string encryptedMessage;  
    for (char c : message) {
        if (baconMap.find(c) != baconMap.end()) {
            encryptedMessage += baconMap[c];
        } else {
            encryptedMessage += c;
        }
    }

    return encryptedMessage;
}

// Функция расшифровки сообщения с помощью шифра Бэкона
string baconDecryption(const string& message) {
    map<string, char> baconMap = {
        {"AAAAA", 'A'}, {"AAAAB", 'B'}, {"AAABA", 'C'}, {"AAABB", 'D'},
        {"AABAA", 'E'}, {"AABAB", 'F'}, {"AABBA", 'G'}, {"AABBB", 'H'},
        {"ABAAA", 'I'}, {"ABAAB", 'J'}, {"ABABA", 'K'}, {"ABABB", 'L'},
        {"ABBAA", 'M'}, {"ABBAB", 'N'}, {"ABBBA", 'O'}, {"ABBBB", 'P'},
        {"BAAAA", 'Q'}, {"BAAAB", 'R'}, {"BAABA", 'S'}, {"BAABB", 'T'},
        {"BABAA", 'U'}, {"BABAB", 'V'}, {"BABBA", 'W'}, {"BABBB", 'X'},
        {"BBAAA", 'Y'}, {"BBAAB", 'Z'},
        {"aaaaa", 'a'}, {"aaaab", 'b'}, {"aaaba", 'c'}, {"aaabb", 'd'},
        {"aabaa", 'e'}, {"aabab", 'f'}, {"aabba", 'g'}, {"aabbb", 'h'},
        {"abaaa", 'i'}, {"abaab", 'j'}, {"ababa", 'k'}, {"ababb", 'l'},
        {"abbaaa", 'm'}, {"abbab", 'n'}, {"abbba", 'o'}, {"abbbb", 'p'},
        {"baaaa", 'q'}, {"baaab", 'r'}, {"baaba", 's'}, {"baabb", 't'},
        {"babaa", 'u'}, {"babab", 'v'}, {"babba", 'w'}, {"babbb", 'x'},
        {"bbaaa", 'y'}, {"bbaab", 'z'},
        {"ААААА", 'А'}, {"ААААB", 'Б'}, {"АААBА", 'В'}, {"АААBB", 'Г'},
        {"ААBАА", 'Д'}, {"ААBАB", 'Е'}, {"ААBАB", 'Ё'}, {"ААBBА", 'Ж'},
        {"ААBBB", 'З'}, {"АBААА", 'И'}, {"АBААB", 'Й'}, {"АBАBА", 'К'},
        {"АBАBB", 'Л'}, {"АBBАА", 'М'}, {"АBBАB", 'Н'}, {"АBBBА", 'О'},
        {"АBBBB", 'П'}, {"BАААА", 'Р'}, {"BАААB", 'С'}, {"BААBА", 'Т'},
        {"BААBB", 'У'}, {"BАBАА", 'Ф'}, {"BАBАB", 'Х'}, {"BАBBА", 'Ц'},
        {"BАBBB", 'Ч'}, {"BBААА", 'Ш'}, {"BBААB", 'Щ'}, {"BBАBА", 'Ъ'},
        {"BBАBB", 'Ы'}, {"BBBАА", 'Ь'}, {"BBBАB", 'Э'}, {"BBBBА", 'Ю'},
        {"BBBBB", 'Я'},
        {"ааааа", 'а'}, {"ааааb", 'б'}, {"аааbа", 'в'}, {"аааbb", 'г'},
        {"ааbаа", 'д'}, {"ааbаb", 'е'}, {"ааbаb", 'ё'}, {"ааbbа", 'ж'},
        {"ааbbb", 'з'}, {"аbааа", 'и'}, {"аbааb", 'й'}, {"аbаbа", 'к'},
        {"аbаbb", 'л'}, {"аbbаа", 'м'}, {"аbbаb", 'н'}, {"аbbbа", 'о'},
        {"аbbbb", 'п'}, {"bаааа", 'р'}, {"bаааb", 'с'}, {"bааbа", 'т'},
        {"bааbb", 'у'}, {"bаbаа", 'ф'}, {"bаbаb", 'х'}, {"bаbbа", 'ц'},
        {"bаbbb", 'ч'}, {"bbааа", 'ш'}, {"bbааb", 'щ'}, {"bbаbа", 'ъ'},
        {"bbаbb", 'ы'}, {"bbbаа", 'ь'}, {"bbbаb", 'э'}, {"bbbbа", 'ю'},
        {"bbbbb", 'я'}
    };

    string decryptedMessage;
    string filteredMessage;

    // Удаление недопустимых символов
    for (char c : message) {
        if (c == 'A' || c == 'B' || c == 'a' || c == 'b' || c == 'А' || c == 'B' || c == 'а' || c == 'b') {
            filteredMessage += c;
        }
    }

    // Дешифровка
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
