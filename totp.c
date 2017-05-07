#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/hmac.h>
#include "sqlite3.h"

#define ALGO_SHA1   1
#define ALGO_SHA256 2
#define ALGO_SHA512 3

typedef struct key {
    size_t len;
    unsigned char *K;
}key;

static key* key_from_b32(char *b32_str) {
    assert(strlen(b32_str)%8==0);
    unsigned char *decoded = malloc((strlen(b32_str)/8)*5);
    size_t decode_n = 0;
    for (unsigned long i=0; i<strlen(b32_str); i+=8) {
        uint64_t acc = 0;
        for (int j=0; j<8; j++) {
            char ch = b32_str[i+j];
            int add_num = 0;
            if ('A' <= ch && ch <= 'Z') {
                add_num = ch - 'A';
                assert(add_num<=26);
            } else if ('2' <= ch && ch <= '7') {
                add_num = (ch - '2') + 26;
                assert(add_num>26);
                assert(add_num<=31);
            }
            acc = (acc << 5) + add_num;
        }
        for (int k=4; k>=0; k--) {
            decoded[decode_n+k] = acc % 256;
            acc /= 256;
        }
        decode_n += 5;
    }

    key *k = malloc(sizeof(key));
    k -> len = (strlen(b32_str)/8)*5;
    k -> K = decoded;
    
    return k;
}

char *generate_TOTP(key *k, uint64_t time, uint8_t digits, uint8_t algo) {
    const EVP_MD *type = NULL;
    switch (algo) {
        case ALGO_SHA1:
            type = EVP_sha1();
            break;
        case ALGO_SHA256:
            type = EVP_sha256();
            break;
        case ALGO_SHA512:
            type = EVP_sha512();
            break;
        default:
            assert(false);
    }
    unsigned int len = 0;
    time = htobe64(time);
    unsigned char *hash = HMAC(type, k->K, k->len, (unsigned char*)&time, sizeof(time), NULL, &len);
    int offset = hash[len-1] & 0xf;

    int binary =
         ((hash[offset] & 0x7f) << 24)     |
         ((hash[offset + 1] & 0xff) << 16) |
         ((hash[offset + 2] & 0xff) << 8)  |
         ( hash[offset + 3] & 0xff);

    uint64_t DIGITS_POWER[] = {1,10,100,1000,10000,100000,1000000,10000000,100000000};

    int otp = binary % DIGITS_POWER[digits];
    char *result = malloc(digits+1);
    sprintf(result, "%0*d", digits, otp);

    assert(strlen(result)==digits);

    return result;
}

void self_test() {
    uint8_t buf[EVP_MAX_MD_SIZE];

    uint8_t empty_char[0] = {};

    uint8_t empty_md5[] = {0x74, 0xe6, 0xf7, 0x29, 0x8a, 0x9c, 0x2d, 0x16,
                           0x89, 0x35, 0xf5, 0x8c, 0x00, 0x1b, 0xad, 0x88};
    
    uint8_t empty_sha1[] = {0xfb, 0xdb, 0x1d, 0x1b, 0x18, 0xaa, 0x6c, 0x08, 0x32, 0x4b,
                            0x7d, 0x64, 0xb7, 0x1f, 0xb7, 0x63, 0x70, 0x69, 0x0e, 0x1d};

    uint8_t empty_sha256[] = {0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec,
                              0x77, 0x2f, 0x95, 0xd7, 0x78, 0xc3, 0x5f, 0xc5,
                              0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53,
                              0xc6, 0xc7, 0x12, 0x14, 0x42, 0x92, 0xc5, 0xad};

    uint8_t fox_md5[] = {0x80, 0x07, 0x07, 0x13, 0x46, 0x3e, 0x77, 0x49,
                         0xb9, 0x0c, 0x2d, 0xc2, 0x49, 0x11, 0xe2, 0x75};

    uint8_t fox_sha1[] = {0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a,
                          0x7a, 0x36, 0xf7, 0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9};

    uint8_t fox_sha256[] = {0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
                            0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
                            0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
                            0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8};

    HMAC(EVP_md5(), empty_char, 0, empty_char, 0, buf, NULL);
    assert(memcmp(buf, empty_md5, sizeof(empty_md5)) == 0);
    HMAC(EVP_sha1(), empty_char, 0, empty_char, 0, buf, NULL);
    assert(memcmp(buf, empty_sha1, sizeof(empty_sha1)) == 0);
    HMAC(EVP_sha256(), empty_char, 0, empty_char, 0, buf, NULL);
    assert(memcmp(buf, empty_sha256, sizeof(empty_sha256)) == 0);


    HMAC(EVP_md5(), "key", 3, (unsigned char*)"The quick brown fox jumps over the lazy dog", 43, buf, NULL);
    assert(memcmp(buf, fox_md5, sizeof(fox_md5)) == 0);
    HMAC(EVP_sha1(), "key", 3, (unsigned char*)"The quick brown fox jumps over the lazy dog", 43, buf, NULL);
    assert(memcmp(buf, fox_sha1, sizeof(fox_sha1)) == 0);
    HMAC(EVP_sha256(), "key", 3, (unsigned char*)"The quick brown fox jumps over the lazy dog", 43, buf, NULL);
    assert(memcmp(buf, fox_sha256, sizeof(fox_sha256)) == 0);


    key *k;

    k = key_from_b32("MZXW6YTB");
    assert(memcmp(k->K, (unsigned char*)"fooba", 5) == 0);
    assert(k->len == 5);

    k->K = (unsigned char*)"12345678901234567890";
    k->len = 20;

    assert(strcmp(
        generate_TOTP(k, 0x0000000000000001, 8, ALGO_SHA1),
        "94287082") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x00000000023523EC, 8, ALGO_SHA1),
        "07081804") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x00000000023523ED, 8, ALGO_SHA1),
        "14050471") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x000000000273EF07, 8, ALGO_SHA1),
        "89005924") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x0000000003F940AA, 8, ALGO_SHA1),
        "69279037") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x0000000027BC86AA, 8, ALGO_SHA1),
        "65353130") == 0);
    k->K = (unsigned char*)"12345678901234567890123456789012";
    k->len = 32;
    assert(strcmp(
        generate_TOTP(k, 0x0000000000000001, 8, ALGO_SHA256),
        "46119246") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x00000000023523EC, 8, ALGO_SHA256),
        "68084774") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x00000000023523ED, 8, ALGO_SHA256),
        "67062674") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x000000000273EF07, 8, ALGO_SHA256),
        "91819424") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x0000000003F940AA, 8, ALGO_SHA256),
        "90698825") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x0000000027BC86AA, 8, ALGO_SHA256),
        "77737706") == 0);
    k->K = (unsigned char*)"1234567890123456789012345678901234567890123456789012345678901234";
    k->len = 64;
    assert(strcmp(
        generate_TOTP(k, 0x0000000000000001, 8, ALGO_SHA512),
        "90693936") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x00000000023523EC, 8, ALGO_SHA512),
        "25091201") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x00000000023523ED, 8, ALGO_SHA512),
        "99943326") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x000000000273EF07, 8, ALGO_SHA512),
        "93441116") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x0000000003F940AA, 8, ALGO_SHA512),
        "38618901") == 0);
    assert(strcmp(
        generate_TOTP(k, 0x0000000027BC86AA, 8, ALGO_SHA512),
        "47863826") == 0);


    k = key_from_b32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert(strcmp(
        generate_TOTP(k, 0x0000000088888888, 6, ALGO_SHA1),
        "596617") == 0);
}

void init_database(sqlite3 *conn) {
    // This function assumes that the database is empty.
    // It won't do any damage to a database that already exists.
    // To reset a database that exists, delete the file on the file system
    //   and then call this function
    
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(
        conn,
        "CREATE TABLE IF NOT EXISTS tokens("
            "name TEXT, "
            "key BLOB, "
            "digits INTEGER, "
            "algo TEXT, "
            "immutable BOOL, " // SQLite has no boolean class, this is equal to int
            "type TEXT, "
            "description TEXT"
        ");",
        -1,
        &stmt,
        NULL
    );

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        printf("init_database error: %s\n", sqlite3_errmsg(conn));
    }
}

void uninit_database(sqlite3 *conn) {
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(
        conn,
        "DROP TABLE IF EXISTS tokens",
        -1,
        &stmt,
        NULL
    );

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        printf("reset_database error: %s\n", sqlite3_errmsg(conn));
    }
}

int main() {
    self_test();
    printf("Self tests all passed\n");
    sqlite3 *conn;
    sqlite3_open("tokens.db", &conn);
    uninit_database(conn);
    init_database(conn);

    char input[256];
    const char *prompt = "> ";

    printf("%s", prompt);
    while(fgets(input, sizeof(input), stdin) != NULL) {
        printf("%s", prompt);
    }

    sqlite3_close(conn);
}
