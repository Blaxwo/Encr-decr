#include <iostream>
#include <vector>
#include <cstdint>
using namespace std;

#define LB32_MASK 0x00000001
#define LB64_MASK 0x0000000000000001
#define L64_MASK 0x00000000ffffffff
#define H64_MASK 0xffffffff00000000

typedef uint64_t ui64;
typedef uint32_t ui32;
typedef uint8_t ui8;

class DES {
public:
    explicit DES(const vector<ui8>& key) {
        ui64 adjusted_key = adjust_key(key);
        keygen(adjusted_key);
    }

    vector<ui8> encrypt(const vector<ui8>& data) {
        return process_data(data, false);
    }

    vector<ui8> decrypt(const vector<ui8>& data) {
        return process_data(data, true);
    }

private:
    void keygen(ui64 key);
    ui64 des(ui64 block, bool mode);
    ui64 ip(ui64 block);
    ui64 fp(ui64 block);
    void feistel(ui32& L, ui32& R, ui32 F);
    ui32 f(ui32 R, ui64 k);

    ui64 sub_key[16];

    ui64 adjust_key(const vector<ui8>& key) {
        ui64 adjusted_key = 0;
        for (size_t i = 0; i < min(key.size(), (size_t)8); ++i) {
            adjusted_key |= (ui64)key[i] << (56 - i * 8);
        }
        return adjusted_key;
    }

    vector<ui8> process_data(const vector<ui8>& data, bool mode) {
        vector<ui8> result;
        size_t num_blocks = (data.size() + 7) / 8;

        for (size_t i = 0; i < num_blocks; ++i) {
            ui64 block = 0;
            for (size_t j = 0; j < 8 && i * 8 + j < data.size(); ++j) {
                block |= (ui64)data[i * 8 + j] << (56 - j * 8);
            }

            ui64 processed_block = des(block, mode);

            for (int j = 0; j < 8; ++j) {
                result.push_back((processed_block >> (56 - j * 8)) & 0xFF);
            }
        }
        return result;
    }
};

static const char PC1[] = {
        57, 49, 41, 33, 25, 17,  9,
        1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,

        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
};

static const char PC2[] = {
        14, 17, 11, 24,  1,  5,
        3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
};

static const char ITERATION_SHIFT[] = {
//  1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16
        1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1
};
static const char IP[] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
};

static const char FP[] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25
};

static const char EXPANSION[] = {
        32,  1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
};

static const char PBOX[] = {
        16,  7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
};

static const char SBOX[8][64] = {
        { // S1
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
        { // S2
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
        { // S3
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
        { // S4
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
        { // S5
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
        { // S6
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
        { // S7
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
        { // S8
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
};

void DES::keygen(ui64 key)
{
    ui64 permuted_choice_1 = 0;
    for (ui8 i = 0; i < 56; i++) {
        permuted_choice_1 <<= 1;
        permuted_choice_1 |= (key >> (64 - PC1[i])) & LB64_MASK;
    }

    ui32 C = (ui32)((permuted_choice_1 >> 28) & 0x000000000fffffff);
    ui32 D = (ui32)(permuted_choice_1 & 0x000000000fffffff);

    for (ui8 i = 0; i < 16; i++) {
        for (ui8 j = 0; j < ITERATION_SHIFT[i]; j++) {
            C = (0x0fffffff & (C << 1)) | (0x00000001 & (C >> 27));
            D = (0x0fffffff & (D << 1)) | (0x00000001 & (D >> 27));
        }

        ui64 permuted_choice_2 = (((ui64)C) << 28) | (ui64)D;

        sub_key[i] = 0;
        for (ui8 j = 0; j < 48; j++) {
            sub_key[i] <<= 1;
            sub_key[i] |= (permuted_choice_2 >> (56 - PC2[j])) & LB64_MASK;
        }
    }
}

ui64 DES::des(ui64 block, bool mode)
{
    block = ip(block);

    ui32 L = (ui32)(block >> 32) & L64_MASK;
    ui32 R = (ui32)(block & L64_MASK);

    for (ui8 i = 0; i < 16; i++) {
        ui32 F = mode ? f(R, sub_key[15 - i]) : f(R, sub_key[i]);
        feistel(L, R, F);
    }

    block = (((ui64)R) << 32) | (ui64)L;

    return fp(block);
}

ui64 DES::ip(ui64 block)
{
    ui64 result = 0;
    for (ui8 i = 0; i < 64; i++) {
        result <<= 1;
        result |= (block >> (64 - IP[i])) & LB64_MASK;
    }
    return result;
}

ui64 DES::fp(ui64 block)
{
    ui64 result = 0;
    for (ui8 i = 0; i < 64; i++) {
        result <<= 1;
        result |= (block >> (64 - FP[i])) & LB64_MASK;
    }
    return result;
}

void DES::feistel(ui32& L, ui32& R, ui32 F)
{
    ui32 temp = R;
    R = L ^ F;
    L = temp;
}

ui32 DES::f(ui32 R, ui64 k)
{
    ui64 s_input = 0;
    for (ui8 i = 0; i < 48; i++) {
        s_input <<= 1;
        s_input |= (ui64)((R >> (32 - EXPANSION[i])) & LB32_MASK);
    }

    s_input = s_input ^ k;

    ui32 s_output = 0;
    for (ui8 i = 0; i < 8; i++) {
        char row = (char)((s_input & (0x0000840000000000 >> 6 * i)) >> (42 - 6 * i));
        row = (row >> 4) | (row & 0x01);

        char column = (char)((s_input & (0x0000780000000000 >> 6 * i)) >> (43 - 6 * i));

        s_output <<= 4;
        s_output |= (ui32)(SBOX[i][16 * row + column] & 0x0f);
    }

    ui32 f_result = 0;
    for (ui8 i = 0; i < 32; i++) {
        f_result <<= 1;
        f_result |= (s_output >> (32 - PBOX[i])) & LB32_MASK;
    }

    return f_result;
}

int main() {
    vector<ui8> key = {0x13, 0x34};

    cout << "Введіть дані для шифрування: ";
    string input;
    getline(cin, input);

    vector<ui8> data(input.begin(), input.end());

    DES des(key);
    vector<ui8> encrypted = des.encrypt(data);

    cout << "Зашифровані дані: ";
    for (ui8 byte : encrypted) {
        printf("%02X ", byte);
    }
    cout << endl;

    string encrypted_text(encrypted.begin(), encrypted.end());

    cout << "Зашифровані дані (слово): " << encrypted_text << endl;

    vector<ui8> decrypted = des.decrypt(encrypted);

    string decrypted_text(decrypted.begin(), decrypted.end());

    cout << "Розшифровані дані: " << decrypted_text << endl;

    return 0;
}

