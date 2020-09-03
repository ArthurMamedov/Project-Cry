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


template<typename _F, typename... _Args>
unsigned long long take_time(_F func, _Args... args...) {
	auto begin = clock();
	func(args...);
	auto end = clock() - begin;
	return end;
}


void print_array(uint8_t* array, size_t length) {
	printf("[ ");
	for (size_t i = 0; i < length; ++i)
		printf("%d ", array[i]);
	printf("]\n");
}

inline void mul(const bool* first, const bool* second, bool* result) {
	for (size_t c = 0; c < 10; c++)
		for (size_t p = 0; p < 10; p++)
			result[c + p] = result[c + p] ^ first[c] & second[p];
}


inline void bin(uint16_t num) {
	for (short i = 15; i >= 0; i--)
		std::cout << ((num >> i) & 1);
	std::cout << std::endl;
}


inline uint16_t upped_mul(uint8_t f, uint8_t s) {
	uint16_t r = 0;
	for (int c = 8; c >= 0; c--) { //invert the loop to invert the result num.
		r = r << 1;
		if ((f >> c) & 1)
			r = r ^ s;
	}
	return r;
}


inline uint8_t upped_mod(uint16_t num, uint16_t modulo = 0b100011011) {
	int i = 15;
	while (num >= modulo) {
		for (; i >= 0; i--) {
			bool tmp = (num >> i) & 1;
			if (tmp) {
				break;
			}
		}
		num = num ^ (modulo << (i - 8));
	}
	return num;
}


int main(int argc, char** argv) {
	using namespace std;
	
	/*uint8_t a = 0b10010001;
	uint8_t b = 0b00100100;
	bin(upped_mul(a, b));*/

	//uint8_t msg[49] = "Lorem Ipsum is simply dummy text of the printin";

	//AES aes("0123456789abcdef");
	//aes.encrypt(msg);
	//aes.decrypt(msg);
	//cout << msg << endl;


	/*res = 0b0000000010000000;

	cout << "res: " << res << endl;
	bin(res << 1);
	cout << "res: " << (res<<1) << endl;*/




	//Cry encrypt file.txt AES key
	// argv[1] = encrypt | decrypt
	// argv[2] = file name
	// argv[3] = algorithm name
	// argv[4] = key
	HANDLE color = GetStdHandle(STD_OUTPUT_HANDLE);
	if (argc != 5) {
		cout << "Here must be the instruction, but i'm too lazy to write it right now...\n";
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