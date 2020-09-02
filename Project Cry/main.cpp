#include<iostream>
#include<string>
#include<conio.h>
#include<ctime>
#include<vector>
#include<algorithm>
#include<Windows.h>
#include"algorithms.hpp"


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


int main(int argc, char** argv) {
	using namespace std;
	
	GOST28147_89 gst("0123456789qwertyuiopasdfghjklzxc");
	uint8_t msg[49] = "Lorem Ipsum is simply dummy text of the printing";
	gst.encrypt(msg);
	gst.decrypt(msg);
	cout << msg;

	/*try {
		file_cryptor fl(factory::create(argv[1], argv[2]));
		fl.in_place = true;
		std::string s = argv[3];
		if (s == "e")
			fl.encrypt_file("file.txt");
		else if (s == "d")
			fl.decrypt_file("file.txt.enc");
		else cout << "Error!" << endl;
	}
	catch (std::exception& ex) {
		cout << ex.what() << endl;
	}*/
	

	return 0;
}