#include<iostream>
#include<conio.h>
#include"algorithms.hpp"
#define BLOCK_LENGTH 48


file_cryptor::file_cryptor(const std::shared_ptr<cryptor>& cryptor, bool in_place) {
	this->cryptint_algorithm = cryptor;
	this->in_place = in_place;
}


void file_cryptor::set_crypting_algorithm(const std::shared_ptr<cryptor>& cryptor) {
	this->cryptint_algorithm = cryptor;
}


void file_cryptor::encrypt_file(const std::string& path_to_file) {
	std::ifstream reader(path_to_file, std::ifstream::in | std::ifstream::binary);
	std::ofstream writer(path_to_file + ".enc", std::ofstream::out | std::ofstream::binary);

	if (!reader.is_open() || !writer.is_open())
		throw std::exception("Didn't manage to open the file.");

	uint8_t block[BLOCK_LENGTH];
	bool end_file = false;
	short count;

	while (!end_file) {
		reader.read((char*)block, BLOCK_LENGTH);
		count = static_cast<short>(reader.gcount());

		if (count < BLOCK_LENGTH) {
			for (size_t i = count; i < BLOCK_LENGTH; i++)
				block[i] = 0;
			end_file = true;
		}

		cryptint_algorithm->encrypt(block);

		writer.write((char*)block, BLOCK_LENGTH);
		if (end_file)
			writer.write((char*)&count, 1);
	}

	reader.close();
	writer.close();

	if (in_place) {
		std::string _ = "del " + path_to_file;
		system(_.c_str());
	}
}


void file_cryptor::decrypt_file(const std::string& path_to_file) {
	if (path_to_file.find(".enc", path_to_file.size() - 4) == (size_t)-1)
		throw std::exception("This file hasn't been crypted.");
	
	std::ifstream reader(path_to_file, std::ifstream::binary | std::ifstream::in);
	std::ofstream writer(path_to_file.substr(0, path_to_file.size() - 4), std::ofstream::binary | std::ofstream::out);

	if (!reader.is_open() || !writer.is_open())
		throw std::exception("Didn't manage to open the file.");

	uint8_t block[BLOCK_LENGTH], check[2];

	while (true) {
		reader.read((char*)block, BLOCK_LENGTH);
		cryptint_algorithm->decrypt(block);

		reader.read(reinterpret_cast<char*>(check), 2);
		if (reader.gcount() == 1) {
			writer.write(reinterpret_cast<char*>(block), check[0]);
			break;
		}
		else
			writer.write((char*)block, BLOCK_LENGTH);
		reader.seekg(reader.tellg().operator-(2));
	}

	reader.close();
	writer.close();

	
	if (in_place) {
		std::string _ = "del " + path_to_file;
		system(_.c_str());
	}
}
