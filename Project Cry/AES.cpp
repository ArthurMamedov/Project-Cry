#include<string>
#include<future>
#include"algorithms.hpp"
#define EXT_KEY_LENGTH 176


#pragma region auxilary functions
	template<typename T>
	inline void AES::rewrite (T& msg, const std::future<void>& w, size_t i, size_t shift, uint8_t block[16]) {
		w.wait();
		memcpy(&msg[i + shift], block, 16);
	}


	inline uint8_t AES::mul(uint8_t first, uint8_t second) {
		uint16_t r = 0;
		for (int c = 7; c >= 0; c--) {
			r = r << 1;
			if ((first >> c) & 1)
				r = r ^ second;
		}
		return r;
	}


	inline uint8_t AES::mod(uint16_t num, uint16_t modulo) {
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


	inline uint8_t AES::pol_mul(uint8_t f, uint8_t s) {
		auto res = mul(f, s);
		return mod(res, 0b100011011);
	}

	
	inline void AES::key_extension(const char* key, uint8_t* ext_key) {
		uint8_t Rcon[258];
		Rcon[0] = 1; Rcon[257] = Rcon[256] = Rcon[255] = 0;

		for (size_t i = 1; i < 255; i++)
			Rcon[i] = pol_mul(2, Rcon[i - 1]);

		for (size_t i = 0; i < 16; i++)
			ext_key[i] = key[i];

		for (size_t c = 16; c < EXT_KEY_LENGTH; c += 4) {
			size_t i = static_cast<size_t>(c / 4);
			if (!(i % 4)) {
				uint8_t rotated[4];

				rot_byte(&ext_key[c - 4], rotated);

				for (size_t p = 0; p < 4; p++) {
					sub_byte(rotated[p]);
					ext_key[c + p] = rotated[p] ^ Rcon[i / 4];
				}
			}
			else {
				for (size_t p = 0; p < 4; p++)
					ext_key[c + p] = ext_key[c - 16 + p] ^ ext_key[c - 4 + p];
			}
		}
	}
#pragma endregion


#pragma region encription
	inline void AES::rot_byte(const uint8_t* byte, uint8_t* to) {  //Takes the word 4 bytes long.
		memcpy(to, byte, 4);
		std::swap(to[0], to[3]);
	}


	inline void AES::sub_byte(uint8_t& byte) {
		uint8_t f = byte >> 4;
		uint8_t s = byte ^ (f << 4);
		byte = Sbox[f][s];
	}


	inline void AES::sub_bytes(uint8_t* state) {
		for (size_t c = 0; c < 16; c++)
			sub_byte(state[c]);
	}


	inline void AES::add_round_key(uint8_t* state, uint8_t* round_key) {
		for (size_t i = 0; i < 16; i++)
			state[i] ^= round_key[i];
	}


	inline void AES::shift(size_t from, uint8_t* state) {
		for (size_t i = from; i < from + 3; i++)
			std::swap(state[i], state[i + 1]);
	}


	inline void AES::shift_rows(uint8_t* state) {
		shift(4, state);
		shift(8, state);
		shift(8, state);
		shift(12, state);
		shift(12, state);
		shift(12, state);
	}


	inline void AES::mix_colums(uint8_t* state) {  //a = 3x^3 + 1x^2 + 1x^2 + 2
		uint8_t new_state[16]; // 01101001  x^6 + x^5 + x^3 + 1
		for (size_t i = 0; i < 4; i++) {
			new_state[i] = pol_mul(2, state[i]) ^ pol_mul(3, state[i + 4]) ^ state[i + 8] ^ state[i + 12];
			new_state[i + 4] = state[i] ^ pol_mul(2, state[i + 4]) ^ pol_mul(3, state[i + 8]) ^ state[i + 12];
			new_state[i + 8] = state[i] ^ state[i + 4] ^ pol_mul(2, state[i + 8]) ^ pol_mul(3, state[i + 12]);
			new_state[i + 12] = pol_mul(3, state[i]) ^ state[i + 4] ^ state[i + 8] ^ pol_mul(2, state[i + 12]);
		}
		memmove(state, new_state, 16);
	}


	inline void AES::split_key(const char* key, uint8_t first[16], uint8_t middle[9][16], uint8_t last[16]) {
		uint8_t ext_key[EXT_KEY_LENGTH];
		key_extension(key, ext_key);
		for (size_t c = 0; c < 16; c++) {
			first[c] = ext_key[c];
			last[c] = ext_key[160 + c];
		}
		for (size_t c = 0; c < 9; c++)
			for (size_t p = 0; p < 16; p++)
				middle[c][p] = ext_key[16 + c * 16 + p];
	}


	void AES::encrypt(uint8_t block[48]) {
		uint8_t block1[16], block2[16], block3[16];
		std::future<void> w1, w2, w3;
		const auto _encrypt = [&](uint8_t block[16]) {
			add_round_key(block, first);
			for (size_t k = 0; k < 9; k++) {
				sub_bytes(block);
				shift_rows(block);
				mix_colums(block);
				add_round_key(block, middle[k]);
			}
			sub_bytes(block);
			shift_rows(block);
			add_round_key(block, last);
		};
		for (size_t c = 0; c < 16; c++) {
			block1[c] = block[c];
			block2[c] = block[16 + c];
			block3[c] = block[32 + c];
		}

		w1 = std::async(std::launch::async, _encrypt, block1);
		w2 = std::async(std::launch::async, _encrypt, block2);
		w3 = std::async(std::launch::async, _encrypt, block3);

		rewrite(block, w1, 0, 0, block1);
		rewrite(block, w2, 0, 16, block2);
		rewrite(block, w3, 0, 32, block3);
	}
#pragma endregion


#pragma region decryption
	inline void AES::inv_sub_byte(uint8_t& byte) {
		uint8_t f = byte >> 4;
		uint8_t s = byte ^ (f << 4);
		byte = inv_Sbox[f][s];
	}


	inline void AES::inv_sub_bytes(uint8_t* state) {
		for (size_t c = 0; c < 16; c++)
			inv_sub_byte(state[c]);
	}


	inline void AES::inv_mix_colums(uint8_t* state) {  //d = 0bx^3 + 0dx^2 +9x + e
		uint8_t new_state[16];
		for (size_t i = 0; i < 4; i++) {
			new_state[i] = pol_mul(14, state[i]) ^ pol_mul(11, state[i + 4]) ^ pol_mul(13, state[i + 8]) ^ pol_mul(9, state[i + 12]);
			new_state[i + 4] = pol_mul(9, state[i]) ^ pol_mul(14, state[i + 4]) ^ pol_mul(11, state[i + 8]) ^ pol_mul(13, state[i + 12]);
			new_state[i + 8] = pol_mul(13, state[i]) ^ pol_mul(9, state[i + 4]) ^ pol_mul(14, state[i + 8]) ^ pol_mul(11, state[i + 12]);
			new_state[i + 12] = pol_mul(11, state[i]) ^ pol_mul(13, state[i + 4]) ^ pol_mul(9, state[i + 8]) ^ pol_mul(14, state[i + 12]);
		}
		memmove(state, new_state, 16);
	}


	inline void AES::inv_shift_rows(uint8_t* state) {
		shift(4, state);
		shift(4, state);
		shift(4, state);
		shift(8, state);
		shift(8, state);
		shift(12, state);
	}


	void AES::decrypt(uint8_t block[48]) {
		uint8_t block1[16], block2[16], block3[16];
		std::future<void> w1, w2, w3;
		const auto _decrypt = [&](uint8_t block[16]) {
			add_round_key(block, last);
			inv_shift_rows(block);
			inv_sub_bytes(block);
			for (size_t c = 0; c < 9; c++) {
				add_round_key(block, middle[9 - c - 1]);
				inv_mix_colums(block);
				inv_shift_rows(block);
				inv_sub_bytes(block);
			}
			add_round_key(block, first);
		};
		for (size_t c = 0; c < 16; c++) {
			block1[c] = block[c];
			block2[c] = block[16 + c];
			block3[c] = block[32 + c];
		}

		w1 = std::async(std::launch::async, _decrypt, block1);
		w2 = std::async(std::launch::async, _decrypt, block2);
		w3 = std::async(std::launch::async, _decrypt, block3);

		rewrite(block, w1, 0, 0, block1);
		rewrite(block, w2, 0, 16, block2);
		rewrite(block, w3, 0, 32, block3);
	}
#pragma endregion


	AES::AES(const char* key) {
		if (strlen(key) != 16)
			throw std::exception("Key length for AES must be 16.");
		split_key(key, first, middle, last);
	}


	void AES::change_key(const char* key) {
		if (strlen(key) != 16)
			throw std::exception("Key length for AES must be 16.");
		split_key(key, first, middle, last);
	}