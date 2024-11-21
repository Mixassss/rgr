#include <sstream>

#include "Cryptosystem.h"

typedef unsigned char uc;

// Глобальные переменные для алгоритма Шамира
static int p;   // Простое число
static int cA;  // Секретный ключ Алисы
static int dA;  // Обратный ключ Алисы

// Функция для вычисления наибольшего общего делителя (НОД)
int gcd(int a, int b) {
    while (b != 0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Функция для вычисления мультипликативного обратного числа по модулю m
int modInverse(int a, int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1)
        return 0;

    while (a > 1) {
        q = a / m;
        t = m;

        m = a % m;
        a = t;
        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

// Функция для быстрого возведения в степень по модулю
long long modPow(long long base, long long exponent, long long modulus) {
    if (modulus == 1)
        return 0;
    long long result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1; // Делим показатель на 2
        base = (base * base) % modulus;
    }
    return result;
}

// Функция для генерации ключей для алгоритма Шамира
void generateShamirKeys() {
    // Выбираем простое число p
    p = 257;

    // Подбираем секретный Алисы cA
    cA = 5;

    // Вычисляем обратный ключ dA, такой что cA * dA ? 1 (mod p-1)
    dA = modInverse(cA, p - 1);
}

// Функция для проверки ввода для шифра Шамира
vector<char> checkinputshamir(const string& message) {
    vector<char> invalidChars;
    for (char c : message) {
        // Допустимые символы: буквы (A-Z, a-z) и пробелы
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c == ' ') || (c >= 'А' && c <= 'Я') || (c >= 'а' && c <= 'я') ||
              (c == '!') ||(c == '@') || (c == '"') || (c == '#') ||
              (c == '$') || (c == ';') || (c == '%') || (c == '^') ||
              (c == ':') || (c == '&') || (c == '?') || (c == '*') ||
              (c == '~') || (c == '(') || (c == ')') || (c == '-') ||
              (c == '_') || (c == '+') || (c == '=') || (c== '<') ||
              (c== '>') || (c == '/') || (c == '|') || (c == '.') ||
              (c == ',') || (c == '`'))) {
            invalidChars.push_back(c);
        }
    }
    return invalidChars;
}

// Функция шифрования сообщения с помощью алгоритма Шамира
string shamirEncryption(const string& message) {
    // Преобразуем сообщение в числа
    vector<int> m_numbers;
    for (uc c : message) {
        if (c >= 'A' && c <= 'Z') {
            m_numbers.push_back(c - 'A' + 1); // Преобразуем A-Z в 1-26
        } else if (c >= 'a' && c <= 'z') {
            m_numbers.push_back(c - 'a' + 27); // Преобразуем a-z в 27-52
        } else if (c == ' ') {
            m_numbers.push_back(0); // Представляем пробел как ''
        } else if (c >= uc('А') && c <= uc('Я')) {
            m_numbers.push_back(c - uc('А') + 53); // Преобразуем А-Я в 53-85
        } else if (c >= uc('а') && c <= uc('я')) {
            m_numbers.push_back(c - uc('а') + 86); // Преобразуем а-я в 86-118
        } else {
            m_numbers.push_back(119 + (int)c); // Специальные символы обрабатываем как 119-<n>, где <n> - порядковый номер символа
        }
    }

    // Шифруем: C = M^cA mod p
    vector<int> C_numbers;
    for (int m : m_numbers) {
        int C = modPow(m, cA, p);
        C_numbers.push_back(C);
    }

    // Преобразуем зашифрованные числа в строку
    string encryptedMessage;
    for (int C : C_numbers) {
        encryptedMessage += to_string(C) + " ";
    }

    // Удаляем последний пробел
    if (!encryptedMessage.empty()) {
        encryptedMessage.pop_back();
    }

    return encryptedMessage;
}

// Функция расшифровки сообщения с помощью алгоритма Шамира
string shamirDecryption(const string &message) {
    // Преобразуем зашифрованное сообщение из строки в числа
    vector<int> C_numbers;
    stringstream ss(message);
    string token;
    while (ss >> token) {
        try {
            int C = stoi(token);
            C_numbers.push_back(C);
        } catch (invalid_argument&) { // Если встретился некорректный токен, можно обработать ошибку
        }
    }

    // Расшифровываем: M = C^dA mod p
    vector<int> m_numbers;
    for (int C : C_numbers) {
        int m = modPow(C, dA, p);
        m_numbers.push_back(m);
    }

    // Преобразуем числа обратно в символы
    string decryptedMessage;
    for (int m : m_numbers) {
        if (m == 0) {
            decryptedMessage += ' ';
        } else if (m >= 1 && m <= 26) {
            decryptedMessage += (char)('A' + m - 1);
        } else if (m >= 27 && m <= 52) {
            decryptedMessage += (char)('a' + m - 27);
        } else if (m >= 53 && m <= 85) {
            decryptedMessage += (char)('А' + (m - 53));
        } else if (m >= 86 && m <= 118) {
            decryptedMessage += (char)('а' + (m - 86)); // Русские строчные буквы
        } else if (m >= 119) {
            decryptedMessage += (char)(m - 119); // Обратное преобразование для спец. символов
        }
    }

    return decryptedMessage;
}
