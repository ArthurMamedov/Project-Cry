#include"algorithms.hpp"


inline void GOST28147_89::_64bits_block_to_2_32bit_blocks(const uint8_t block[8], uint32_t& N1, uint32_t& N2) {
    for (int c = 0; c < 4; c++) {
        N1 = (N1 << 8) | block[c];
        N2 = (N2 << 8) | block[c + 4];
    }
}


inline void GOST28147_89::_2_32bits_blocks_to_64_block(uint32_t N1, uint32_t N2, uint8_t block[8]) {
    for (int c = 3; c >= 0; c--) {
        block[c + 4] = N1;
        block[c] = N2;
        N1 = N1 >> 8;
        N2 = N2 >> 8;
    }
}


void GOST28147_89::encrypt(uint8_t msg[48]) {
    std::future<void> w[6];

    auto f = [&](uint8_t msg[8]) {
        uint32_t N1, N2;

        _64bits_block_to_2_32bit_blocks(msg, N1, N2);

        for (uint8_t c = 0; c < 24; c++)
            round(&N1, &N2, round_keys, c);

        for (uint8_t c = 31; c >= 24; c--)
            round(&N1, &N2, round_keys, c);

        _2_32bits_blocks_to_64_block(N1, N2, msg);
    };

    for (size_t c = 0; c < 6; c++)
        w[c] = std::async(std::launch::async, f, &msg[8 * c]);

    for (size_t c = 0; c < 6; c++)
        w[c].wait();
}


void GOST28147_89::decrypt(uint8_t msg[48]) {
    std::future<void> w[6];
    auto f = [&](uint8_t msg[8]) {
        uint32_t N1, N2;

        _64bits_block_to_2_32bit_blocks(msg, N1, N2);

        for (uint8_t c = 0; c < 8; c++)
            round(&N1, &N2, round_keys, c);

        for (uint8_t c = 31; c >= 8; c--)
            round(&N1, &N2, round_keys, c);

        _2_32bits_blocks_to_64_block(N1, N2, msg);
    };

    for (size_t c = 0; c < 6; c++)
        w[c] = std::async(std::launch::async, f, &msg[8 * c]);

    for (size_t c = 0; c < 6; c++)
        w[c].wait();
}


inline void GOST28147_89::round(uint32_t* block32b_1, uint32_t* block32b_2, uint32_t* keys32b, uint8_t i) {
    uint32_t rnd, temp;

    rnd = (*block32b_1 + keys32b[i % 8]) % UINT32_MAX;

    rnd = substitution_table(rnd, i % 8);

    rnd = (rnd << 11) | (rnd >> 21);

    temp = *block32b_1;
    *block32b_1 = rnd ^ *block32b_2;
    *block32b_2 = temp;
}


inline uint32_t GOST28147_89::substitution_table(uint32_t block32b, uint8_t sbox_row) {
    uint8_t blocks4bits[4];
    split_32bits_to_8bits(block32b, blocks4bits);
    substitution_table_by_4bits(blocks4bits, sbox_row);
    return join_4bits_to_32bits(blocks4bits);
}


inline void GOST28147_89::substitution_table_by_4bits(uint8_t* blocks4b, uint8_t sbox_row) {
    uint8_t block4b_1, block4b_2;
    for (uint8_t i = 0; i < 4; ++i) {
        block4b_1 = Sbox[sbox_row][blocks4b[i] & 0x0F];
        block4b_2 = Sbox[sbox_row][blocks4b[i] >> 4];
        blocks4b[i] = block4b_2;
        blocks4b[i] = (blocks4b[i] << 4) | block4b_1;
    }
}


inline void GOST28147_89::split_256bits_to_32bits(const char* key256b) {
    if (strlen(key256b) != 32)
        throw std::exception("Key size mismatch: it must be 32 bytes long.");
    size_t inc = 0;
    for (uint32_t* p32 = round_keys; p32 < round_keys + 8; ++p32) {
        for (uint8_t i = 0; i < 4; ++i)
            *p32 = (*p32 << 8) | (key256b[i + inc]);
        inc += 4;
    }
}


inline void GOST28147_89::split_32bits_to_8bits(uint32_t block32b, uint8_t* blocks8b) {
    for (uint8_t i = 0; i < 4; ++i) {
        blocks8b[i] = (uint8_t)(block32b >> (24 - (i * 8)));
    }
}


inline uint32_t GOST28147_89::join_4bits_to_32bits(uint8_t* blocks4b) {
    uint32_t block32b = 0;
    for (uint8_t i = 0; i < 4; ++i) {
        block32b = (block32b << 8) | blocks4b[i];
    }
    return block32b;
}


GOST28147_89::GOST28147_89(const char* key) {
    if (strlen(key) != 32) {
        throw std::exception("Key length for GOST28147-89 must be 32 bytes long.");
    }
    split_256bits_to_32bits(key);
}


void GOST28147_89::change_key(const char* key) {
    if (strlen(key) != 32) {
        throw std::exception("Key length for GOST28147-89 must be 32 bytes long.");
    }
    split_256bits_to_32bits(key);
}