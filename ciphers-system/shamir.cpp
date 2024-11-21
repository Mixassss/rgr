#include <sstream>

#include "Cryptosystem.h"

typedef unsigned char uc;

// ���������� ���������� ��� ��������� ������
static int p;   // ������� �����
static int cA;  // ��������� ���� �����
static int dA;  // �������� ���� �����

// ������� ��� ���������� ����������� ������ �������� (���)
int gcd(int a, int b) {
    while (b != 0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// ������� ��� ���������� ������������������ ��������� ����� �� ������ m
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

// ������� ��� �������� ���������� � ������� �� ������
long long modPow(long long base, long long exponent, long long modulus) {
    if (modulus == 1)
        return 0;
    long long result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1; // ����� ���������� �� 2
        base = (base * base) % modulus;
    }
    return result;
}

// ������� ��� ��������� ������ ��� ��������� ������
void generateShamirKeys() {
    // �������� ������� ����� p
    p = 257;

    // ��������� ��������� ����� cA
    cA = 5;

    // ��������� �������� ���� dA, ����� ��� cA * dA ? 1 (mod p-1)
    dA = modInverse(cA, p - 1);
}

// ������� ��� �������� ����� ��� ����� ������
vector<char> checkinputshamir(const string& message) {
    vector<char> invalidChars;
    for (char c : message) {
        // ���������� �������: ����� (A-Z, a-z) � �������
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c == ' ') || (c >= '�' && c <= '�') || (c >= '�' && c <= '�') ||
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

// ������� ���������� ��������� � ������� ��������� ������
string shamirEncryption(const string& message) {
    // ����������� ��������� � �����
    vector<int> m_numbers;
    for (uc c : message) {
        if (c >= 'A' && c <= 'Z') {
            m_numbers.push_back(c - 'A' + 1); // ����������� A-Z � 1-26
        } else if (c >= 'a' && c <= 'z') {
            m_numbers.push_back(c - 'a' + 27); // ����������� a-z � 27-52
        } else if (c == ' ') {
            m_numbers.push_back(0); // ������������ ������ ��� ''
        } else if (c >= uc('�') && c <= uc('�')) {
            m_numbers.push_back(c - uc('�') + 53); // ����������� �-� � 53-85
        } else if (c >= uc('�') && c <= uc('�')) {
            m_numbers.push_back(c - uc('�') + 86); // ����������� �-� � 86-118
        } else {
            m_numbers.push_back(119 + (int)c); // ����������� ������� ������������ ��� 119-<n>, ��� <n> - ���������� ����� �������
        }
    }

    // �������: C = M^cA mod p
    vector<int> C_numbers;
    for (int m : m_numbers) {
        int C = modPow(m, cA, p);
        C_numbers.push_back(C);
    }

    // ����������� ������������� ����� � ������
    string encryptedMessage;
    for (int C : C_numbers) {
        encryptedMessage += to_string(C) + " ";
    }

    // ������� ��������� ������
    if (!encryptedMessage.empty()) {
        encryptedMessage.pop_back();
    }

    return encryptedMessage;
}

// ������� ����������� ��������� � ������� ��������� ������
string shamirDecryption(const string &message) {
    // ����������� ������������� ��������� �� ������ � �����
    vector<int> C_numbers;
    stringstream ss(message);
    string token;
    while (ss >> token) {
        try {
            int C = stoi(token);
            C_numbers.push_back(C);
        } catch (invalid_argument&) { // ���� ���������� ������������ �����, ����� ���������� ������
        }
    }

    // ��������������: M = C^dA mod p
    vector<int> m_numbers;
    for (int C : C_numbers) {
        int m = modPow(C, dA, p);
        m_numbers.push_back(m);
    }

    // ����������� ����� ������� � �������
    string decryptedMessage;
    for (int m : m_numbers) {
        if (m == 0) {
            decryptedMessage += ' ';
        } else if (m >= 1 && m <= 26) {
            decryptedMessage += (char)('A' + m - 1);
        } else if (m >= 27 && m <= 52) {
            decryptedMessage += (char)('a' + m - 27);
        } else if (m >= 53 && m <= 85) {
            decryptedMessage += (char)('�' + (m - 53));
        } else if (m >= 86 && m <= 118) {
            decryptedMessage += (char)('�' + (m - 86)); // ������� �������� �����
        } else if (m >= 119) {
            decryptedMessage += (char)(m - 119); // �������� �������������� ��� ����. ��������
        }
    }

    return decryptedMessage;
}
