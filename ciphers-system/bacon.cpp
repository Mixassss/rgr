#include <map>

#include "Cryptosystem.h"

// ������� ��� �������� ����� ��� ����� ������
vector<char> checkinputbacon(const string& message) {
    vector<char> invalidChars;
    for (char c : message) {
        // ���������� �������: ��������� � ������������� �����, ������������� �����, ������
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '�' && c <= '�') || (c >= '�' && c <= '�') || 
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
        
        {'�', "�����"}, {'�', "����B",}, {'�', "���B�"}, {'�', "���BB"},
        {'�', "��B��"}, {'�', "��B�B"}, {'�', "��B�B"}, {'�', "��BB�"},
        {'�', "��BBB"}, {'�', "�B���"}, {'�', "�B��B"}, {'�', "�B�B�"},
        {'�', "�B�BB"}, {'�', "�BB��"}, {'�', "�BB�B"}, {'�', "�BBB�"},
        {'�', "�BBBB"}, {'�', "B����"}, {'�', "B���B"}, {'�', "B��B�"},
        {'�', "B��BB"}, {'�', "B�B��"}, {'�', "B�B�B"}, {'�', "B�BB�"},
        {'�', "B�BBB"}, {'�', "BB���"}, {'�', "BB��B"}, {'�', "BB�B�"},
        {'�', "BB�BB"}, {'�', "BBB��"}, {'�', "BBB�B"}, {'�', "BBBB�"},
        {'�', "BBBBB"},
        {'�', "�����"}, {'�', "����b",}, {'�', "���b�"}, {'�', "���bb"},
        {'�', "��b��"}, {'�', "��b�b"}, {'�', "��b�b"}, {'�', "��bb�"},
        {'�', "��bbb"}, {'�', "�b���"}, {'�', "�b��b"}, {'�', "�b�b�"},
        {'�', "�b�bb"}, {'�', "�bb��"}, {'�', "�bb�b"}, {'�', "�bbb�"},
        {'�', "�bbbb"}, {'�', "b����"}, {'�', "b���b"}, {'�', "b��b�"},
        {'�', "b��bb"}, {'�', "b�b��"}, {'�', "b�b�b"}, {'�', "b�bb�"},
        {'�', "b�bbb"}, {'�', "bb���"}, {'�', "bb��b"}, {'�', "bb�b�"},
        {'�', "bb�bb"}, {'�', "bbb��"}, {'�', "bbb�b"}, {'�', "bbbb�"},
        {'�', "bbbbb"}
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

// ������� ����������� ��������� � ������� ����� ������
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
        {"�����", '�'}, {"����B", '�'}, {"���B�", '�'}, {"���BB", '�'},
        {"��B��", '�'}, {"��B�B", '�'}, {"��B�B", '�'}, {"��BB�", '�'},
        {"��BBB", '�'}, {"�B���", '�'}, {"�B��B", '�'}, {"�B�B�", '�'},
        {"�B�BB", '�'}, {"�BB��", '�'}, {"�BB�B", '�'}, {"�BBB�", '�'},
        {"�BBBB", '�'}, {"B����", '�'}, {"B���B", '�'}, {"B��B�", '�'},
        {"B��BB", '�'}, {"B�B��", '�'}, {"B�B�B", '�'}, {"B�BB�", '�'},
        {"B�BBB", '�'}, {"BB���", '�'}, {"BB��B", '�'}, {"BB�B�", '�'},
        {"BB�BB", '�'}, {"BBB��", '�'}, {"BBB�B", '�'}, {"BBBB�", '�'},
        {"BBBBB", '�'},
        {"�����", '�'}, {"����b", '�'}, {"���b�", '�'}, {"���bb", '�'},
        {"��b��", '�'}, {"��b�b", '�'}, {"��b�b", '�'}, {"��bb�", '�'},
        {"��bbb", '�'}, {"�b���", '�'}, {"�b��b", '�'}, {"�b�b�", '�'},
        {"�b�bb", '�'}, {"�bb��", '�'}, {"�bb�b", '�'}, {"�bbb�", '�'},
        {"�bbbb", '�'}, {"b����", '�'}, {"b���b", '�'}, {"b��b�", '�'},
        {"b��bb", '�'}, {"b�b��", '�'}, {"b�b�b", '�'}, {"b�bb�", '�'},
        {"b�bbb", '�'}, {"bb���", '�'}, {"bb��b", '�'}, {"bb�b�", '�'},
        {"bb�bb", '�'}, {"bbb��", '�'}, {"bbb�b", '�'}, {"bbbb�", '�'},
        {"bbbbb", '�'}
    };

    string decryptedMessage;
    string filteredMessage;

    // �������� ������������ ��������
    for (char c : message) {
        if (c == 'A' || c == 'B' || c == 'a' || c == 'b' || c == '�' || c == 'B' || c == '�' || c == 'b') {
            filteredMessage += c;
        }
    }

    // ����������
    for (size_t i = 0; i < filteredMessage.length(); i += 5) {
        string code = filteredMessage.substr(i, 5);
        if (baconMap.find(code) != baconMap.end()) {
            decryptedMessage += baconMap[code];
        } else {
            decryptedMessage += '?'; // ����������� ���
        }
    }

    return decryptedMessage;
}
