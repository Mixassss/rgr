#ifndef CRYPTOSYSTEM_H
#define CRYPTOSYSTEM_H

// ����������� ����������� ���������
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <ctime>
#include <windows.h>
#include <stdexcept>

using namespace std;

// ���������� ������� ��� ������ � �������
string FileInput(string &filename); // ������� ������ �� �����
string FileOutput(string &filename, string &str); // ������� ������ � ����

// ������� ��� ����� � �������� ��������� ��� �����
void input_and_check(string& message, const string &choice_cipher);

// ������� ��� ���������� � ������������
void Enc_and_Desc(const string &choice_cipher);

// ���������� ���������� ������
extern const string passwd;

#endif // CRYPTOSYSTEM_H
