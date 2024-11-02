#include <sstream>

#include "Cryptosystem.h"

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
    p = 257; // Пример простого числа

    // Генерируем секретный ключ Алисы cA, такой что НОД(cA, p-1) = 1
    do {
        cA = rand() % (p - 2) + 2; // cA в диапазоне [2, p-1]
    } while (gcd(cA, p - 1) != 1);

    // Вычисляем обратный ключ dA, такой что cA * dA ≡ 1 (mod p-1)
    dA = modInverse(cA, p - 1);
}

// Функция для проверки ввода для шифра Шамира
vector<char> checkinputshamir(const string& message) {
    vector<char> invalidChars;
    for (char c : message) {
        // Допустимые символы: буквы (A-Z, a-z) и пробелы
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c == ' ') || (c >= 'А' && c <= 'Я') || (c >= 'а' && c <= 'я'))) {
            invalidChars.push_back(c);
        }
    }
    return invalidChars;
}

// Функция шифрования сообщения с помощью алгоритма Шамира
string shamirEncryption(const string& message) {
    // Преобразуем сообщение в числа
    vector<int> m_numbers;
    for (char c : message) {
        if (c >= 'A' && c <= 'Z') {
            m_numbers.push_back(c - 'A' + 1); // Преобразуем A-Z в 1-26
        } else if (c >= 'a' && c <= 'z') {
            m_numbers.push_back(c - 'a' + 1); // Преобразуем a-z в 1-26
        } else if (c == ' ') {
            m_numbers.push_back(0); // Представляем пробел как 0
        } else if (c >= 'А' && c <= 'Я') {
            m_numbers.push_back(c - 'А' + 27); // Преобразуем А-Я в 27-42
        } else if (c >= 'а' && c <= 'я') {
            m_numbers.push_back(c - 'а' + 43); // Преобразуем а-я в 43-68
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
        } catch (invalid_argument&) {
            // Если встретился некорректный токен, можно обработать ошибку
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
        } else if (m >= 27 && m <= 42) {
            decryptedMessage += (char)('А' + (m - 27));
        } else if (m >= 43 && m <= 68) {
            decryptedMessage += (char)('а' + (m - 43)); // Русские строчные буквы
        }
    }

    return decryptedMessage;
}
