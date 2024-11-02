#ifndef BACON_H
#define BACON_H

#include <string>
#include <vector>

using namespace std;

vector<char> checkinputbacon(const string& message);
string baconEncryption(const string& message);
string baconDecryption(const string& message);

#include "bacon.cpp"

#endif // BACON_H
