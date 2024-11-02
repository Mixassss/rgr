#ifndef SHAMIR_H
#define SHAMIR_H

#include <string>
#include <vector>

using namespace std;

vector<char> checkinputshamir(const string& message);
void generateShamirKeys();
string shamirEncryption(const string& message);
string shamirDecryption(const string& message);

#include "shamir.cpp"

#endif // SHAMIR_H
