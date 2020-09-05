#include<iostream>
#include<string>
#include<conio.h>
#include<ctime>
#include<vector>
#include<chrono>
#include<algorithm>
#include<Windows.h>
#include"algorithms.hpp"
#define DEBUG


std::string help =
"\t\tWELCOM TO PROJECT CRY\n"
"Profect Cry - is a simple file cryptor.\n"
"Now only 2 encryption algorithm are supported: GOST28147-89 and AES.\n"
"\n"
"\t\tHOW to USE\n"
"Cryptor takes 4 parameters:\n"
"[1]: 'encrypt', 'decrypt' and 'help' options - to encrypt, decrypt file or to print help.\n"
"[2]: file path, you would like to decrypt or encrypt.\n"
"[3]: crypting algorithm (AES, GOST)\n"
"[4]: key:\n"
"\tGOST takes 32 bytes long key (example: 0123456789qwertyuiopasdfghjklzxc)\n"
"\tAES takes 16 bytes long key (example: 0123456789abcdef)\n"
""
"That's all...";





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
	if (argc != 5) {
		cout << "Not enought arguments.\n";
		return 0;
	}
	try {
		file_cryptor fl(factory::create(argv[3], argv[4]));
		fl.in_place = true;
		std::string s = argv[3];
		if (!strcmp(argv[1], "encrypt") || !strcmp(argv[1], "ENCRYPT")) {
#ifdef DEBUG
			auto start = std::chrono::high_resolution_clock().now();
#endif
			fl.encrypt_file(argv[2]);
#ifdef DEBUG
			auto stop = std::chrono::high_resolution_clock().now();
#endif
			SetConsoleTextAttribute(color, 10);
			cout << "File " << argv[2] << " successfully encrypted!\n";
			SetConsoleTextAttribute(color, 7);
#ifdef DEBUG
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
			cout << "\tTime spent: " << duration.count() << endl;
#endif
		}
		else if (!strcmp(argv[1], "decrypt") || !strcmp(argv[1], "DECRYPT")) {
#ifdef DEBUG
			auto start = std::chrono::high_resolution_clock().now();
#endif
			fl.decrypt_file(argv[2]);
#ifdef DEBUG
			auto stop = std::chrono::high_resolution_clock().now();
#endif
			SetConsoleTextAttribute(color, 10);
			cout << "File " << argv[2] << " successfully decrypted!\n";
			SetConsoleTextAttribute(color, 7);
#ifdef DEBUG
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
			cout << "\tTime spent: " << duration.count() << endl;
#endif
		}
		else
			throw std::exception("Unknown mode.");
	}
	catch (std::exception& ex) {
		SetConsoleTextAttribute(color, 12);
		cout << "Error!" << endl << '\t';
		SetConsoleTextAttribute(color, 7);
		cout << ex.what() << endl;
	}
	

	return 0;
}