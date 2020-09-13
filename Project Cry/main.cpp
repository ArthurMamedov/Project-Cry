#include <iostream>
#include <string>
#include <conio.h>
#include <ctime>
#include <vector>
#include <chrono>
#include <algorithm>
#include <Windows.h>
#include "algorithms.hpp"
#define DEBUG
#define TEST_FEATURE
#define TAKE_TIME(func, arg, res) \
	auto start = std::chrono::high_resolution_clock::now();\
	func(arg);\
	auto finish = std::chrono::high_resolution_clock::now();\
	res = (std::chrono::duration_cast<std::chrono::milliseconds>(finish - start)).count();


std::string help =
"\t\tWELCOM TO PROJECT CRY\n"
"Profect Cry - is a simple file cryptor.\n"
"Now only 2 encryption algorithm are supported: GOST28147-89 and AES.\n"
"\n"
"\t\tHOW to USE\n"
"Cryptor takes 4 parameters:\n"
"[1]: 'encrypt', 'decrypt' and 'help' options - to encrypt, decrypt file or to print help.\n"
"[2]: file path to a file, you would like to decrypt or encrypt.\n"
"[3]: crypting algorithm (just type the name of it)\n"
"[4]: key:\n"
"\tGOST takes 32 bytes long key (example: 0123456789qwertyuiopasdfghjklzxc)\n"
"\tAES takes 16 bytes long key (example: 0123456789abcdef)\n"
""
"That's all...";


const HANDLE COLOR = GetStdHandle(STD_OUTPUT_HANDLE);


enum colors {
	black, 
	blue,
	green,
	aqua,
	red,
	purple,
	yellow,
	white,
	gray,
	light_blue,
	light_green,
	light_aqua,
	light_red,
	light_purple,
	light_yellow,
	bright_white
};


void good_message(const char* argv, bool encrypt) {
	auto end_word = encrypt ? "encrypted!" : "decrypted!";
	std::cout << "File " << argv << "'s";
	SetConsoleTextAttribute(COLOR, light_green);
	std::cout << " successfully ";
	SetConsoleTextAttribute(COLOR, white);
	std::cout << end_word << std::endl;
}


void bad_message(const char* param) {
	SetConsoleTextAttribute(COLOR, light_red);
	std::cout << "ERROR: ";
	SetConsoleTextAttribute(COLOR, white);
	std::cout << param << std::endl;
}





int main(int argc, char** argv) {
	using namespace std;

	//Cry encrypt file.txt AES key
	// argv[1] = encrypt | decrypt | help
	// argv[2] = file name
	// argv[3] = algorithm name
	// argv[4] = key



	HANDLE color = GetStdHandle(STD_OUTPUT_HANDLE);
	if (argc != 1 && !strcmp(argv[1], "help")) {
		std::cout << help << std::endl;
		return 0;
	}
	if (argc < 5) {
		bad_message("Not enought arguments.");
		return 0;
	}
	for (size_t p = 2; p < argc - 2; p++) {
		try {
			file_cryptor fl(factory::create(argv[argc - 2], argv[argc - 1]));
			if (!strcmp(argv[1], "encrypt") || !strcmp(argv[1], "ENCRYPT")) {
#ifdef DEBUG
				unsigned int time;
				TAKE_TIME(fl.encrypt_file, argv[p], time);
				good_message(argv[p], true);
				std::cout << "\tTime spent: " << time << std::endl;
#else
				fl.encrypt_file(argv[p]);
				good_message(argv[p], true);
#endif //DEBUG
			}
			else if (!strcmp(argv[1], "decrypt") || !strcmp(argv[1], "DECRYPT")) {
#ifdef DEBUG
				unsigned int time;
				TAKE_TIME(fl.decrypt_file, argv[p], time);
				good_message(argv[p], false);
				std::cout << "\tTime spent: " << time << std::endl;
#else
				fl.decrypt_file(argv[p]);
				good_message(argv[p], false);
#endif // DEBUG
			}
			else
				throw std::exception("Unknown mode.");
		}
		catch (std::exception& ex) {
			cout << "COUGHT!!!" << endl;
			bad_message(ex.what());
		}
	}

	return 0;
}