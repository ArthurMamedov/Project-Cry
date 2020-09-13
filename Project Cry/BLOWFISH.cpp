#include <iostream>
#include <string>
#include "algorithms.hpp"
//#define DEBUG


inline void BLOWFISH::split_block(const uint8_t block[8], uint32_t& f, uint32_t& s) {
	for (int c = 0; c < 4; c++) {
		f = (f << 8) | block[c];
		s = (s << 8) | block[c + 4];
	}
#ifdef DEBUG
	std::cout << "64: " << block << ", 32f: " << f << ", 32s: " << s << std::endl;
#endif
}


inline void BLOWFISH::xor_P_block_with_key(const char* key, const size_t key_size) {
	uint32_t f = 0, s = 0, i = 0, buff = 0;
	while (s < 18) {
		if (i % 4 == 0 && i != 0) {
			P_block[s] ^= buff;
			++s;
		}
		buff <<= 8;
		buff ^= key[f];
		++i;
		if (f < key_size) ++f;
		else f = 0;
	}
}


inline void BLOWFISH::key_extension(const char* key) {
	size_t key_size = strlen(key);

	if (key_size > 56 || key_size < 4)
		throw std::exception("Key's length must be bigger than 4 and less than 56 bytes.");

	xor_P_block_with_key(key, key_size);
	key_encryption();
	Sbox_encryption();

#ifdef DEBUG
	for (int c = 0; c < 18; c++) {
		std::cout << P_block[c] << ' ';
	} std::cout << std::endl;
#endif
}


inline void BLOWFISH::key_encryption() {
	uint32_t right = 0, left = 0;
	for (size_t c = 0; c < 18; c += 2) {
		for (size_t p = 0; p < 16; p++)
			round(right, left, P_block[p]);
		right = P_block[c] = right ^ P_block[16];
		left = P_block[c + 1] = left ^ P_block[17];
	}
}


inline void BLOWFISH::Sbox_encryption() {
	auto enc = [&](size_t u) {
		uint32_t right = 0, left = 0;
		for (size_t c = 0; c < 256; c += 2) {
			for (size_t p = 0; p < 16; p++)
				round(right, left, P_block[p]);
			right = Sbox[u][c] = right ^ P_block[16];
			left = Sbox[u][c + 1] = left ^ P_block[17];
		}
	};
	enc(0);
	enc(1);
	enc(2);
	enc(3);
}


inline void BLOWFISH::round(uint32_t& block1, uint32_t& block2, const uint32_t& r_key) {
	uint8_t buff[4];
	const auto tmp1 = block1 ^ r_key;
	memcpy(buff, &tmp1, 4);
	uint32_t result = Sbox[0][buff[0]];
	result += Sbox[1][buff[1]];
	result ^= Sbox[2][buff[2]];
	result += Sbox[3][buff[3]];
	
	auto tmp = block1;
	block1 = result ^ block2;
	block2 = tmp;
}


void BLOWFISH::change_key(const char* new_key) {
	throw std::exception("Not implemented yet...");
}


inline void BLOWFISH::join_32b_block(uint32_t right, uint32_t left, uint8_t block[8]) {
	for (int c = 3; c >= 0; c--) {
		block[c + 4] = right;
		block[c] = left;
		right >>= 8;
		left >>= 8;
	}
}


void BLOWFISH::encrypt(uint8_t msg[48]) {
	std::future<void> w[6];
	auto f = [&](uint8_t block[8]) {
		uint32_t right, left;

		split_block(block, right, left);
		
		for (size_t p = 0; p < 16; p++)
			round(right, left, P_block[p]);
		
		right ^= P_block[16];
		left ^= P_block[17];
		
		join_32b_block(right, left, block);
	};

	for (size_t c = 0; c < 6; c++)
		w[c] = std::async(std::launch::async, f, &msg[8 * c]);

	for (size_t c = 0; c < 6; c++)
		w[c].wait();
}


void BLOWFISH::decrypt(uint8_t msg[48]) {
	std::future<void> w[6];
	auto f = [&](uint8_t block[8]) {
		uint32_t right, left;
		split_block(block, right, left);
		right ^= P_block[17];
		left ^= P_block[16];
		for (int p = 15; p >= 0; p--)
			round(right, left, P_block[p]);
		join_32b_block(right, left, block);
	};

	for (size_t c = 0; c < 6; c++)
		w[c] = std::async(std::launch::async, f, &msg[8 * c]);

	for (size_t c = 0; c < 6; c++)
		w[c].wait();

}


BLOWFISH::BLOWFISH(const char* key) {
	key_extension(key);
}