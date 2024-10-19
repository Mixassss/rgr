#ifndef A1Z26_H
#define A1Z26_H

#include <string>
#include <vector>

using namespace std;

vector<char> checkinputa1z26(string message);
string a1z26Encryption(string message, string key);
string a1z26Decryption(string message, string key);
string generateCipherAlphabet(string key);

#endif // A1Z26_H
