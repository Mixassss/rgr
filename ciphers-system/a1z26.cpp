#include <sstream>

#include "Cryptosystem.h"

typedef unsigned char uc;

int toInt(uc c) {
	int res = int(c);
	if (c >= 'a' && c <= 'z') {
		res = int(c) - 96;
	}
	if (c >= 'A' && c <= 'Z') {
		res = int(c) - 38;
	}
	if (c >= uc('À') && c <= uc('ß')) {
		res = int(c) - 106;
	}
	if (c >= uc('à') && c <= uc('ÿ')) {
		res = int(c) - 171;
	}
	if (c >= ' ' && c <= '@') {
		res = int(c) + 100;
	}
	return res;
}

char toChar(string c) {
	int sym = stoi(c);
	uc res = 0;
	if (sym >= 1 && sym <= 26) {
		res = uc(sym + 96);
	}
	if (sym >= 27 && sym <= 53) {
		res = uc(sym + 38);
	}
	if (sym >= 86 && sym <= 118) {
		res = uc(sym + 106);
	}
	if (sym >= 53 && sym <= 85) {
		res = uc(sym + 171);
	}
	if (sym >= 132 && sym <= 164) {
		res = uc(sym - 100);
	}
	return res;
}

string a1z26Encryption(string text) {
	string crypto;
	for (int i = 0; i < text.size(); i++) {
		crypto += to_string(toInt(text[i])) + '-';
	}
	crypto.pop_back();
	return crypto;
}

string a1z26Decryption(string crypto) {
	string text;
	string sym;
	for (int i = 0; i < crypto.size(); i++) {
		if (crypto[i] != '-') {
			sym += crypto[i];
		}
		else {
			text += toChar(sym);
			sym = "";
		}
	}
	text += toChar(sym);
	sym = "";
	return text;
} 