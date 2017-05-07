#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/hmac.h>
#include "sqlite3.h"
#include <errno.h>
#include <error.h>

#define ALGO_SHA1   1
#define ALGO_SHA256 2
#define ALGO_SHA512 3
#define ERROR(x) (error_at_line(true, true, __FILE__, __LINE__, "%s", (x)))

typedef struct key {
    size_t len;
    unsigned char *K;
}key;

static void set_bit(unsigned char *mem, size_t index) {
    size_t i, pos;
    i = index/8;
    pos = index%8;
    uint8_t flag = 0b10000000 >> pos;
    mem[i] |= flag;
}

static int test_bit_int(uint8_t value, uint8_t index) {
    return ((value) & (1<<index))!=0;
}

static key* key_from_b32(const char *b32_str) {
    unsigned char *decoded = calloc(1, (strlen(b32_str)*5+4)/8);
    if (!decoded) {
        ERROR("malloc failure");
    }
    for (unsigned long i=0; i<strlen(b32_str); i++) {
        char ch = b32_str[i];
        int add_num = 0;
        if ('A' <= ch && ch <= 'Z') {
            add_num = ch - 'A';
            assert(add_num<=26);
        } else if ('2' <= ch && ch <= '7') {
            add_num = (ch - '2') + 26;
            assert(add_num>26);
            assert(add_num<=31);
        } else if (ch == '=') {
            // This means that it's padding and we can break out now
            break;
        } else {
            // Something else.
            // Clean up and return NULL
            free(decoded);
            return NULL;
        }

        if(test_bit_int(add_num, 4))
            set_bit(decoded, i*5);
        if(test_bit_int(add_num, 3))
            set_bit(decoded, i*5+1);
        if(test_bit_int(add_num, 2))
            set_bit(decoded, i*5+2);
        if(test_bit_int(add_num, 1))
            set_bit(decoded, i*5+3);
        if(test_bit_int(add_num, 0))
            set_bit(decoded, i*5+4);
    }

    key *k = malloc(sizeof(key));
    if (!k) {
        error(1, 1, "malloc failure in key_from_b32, exiting");
    }
    k -> len = (strlen(b32_str)/8)*5;
    k -> K = decoded;
    
    return k;
}

void delete_key(key* k) {
    free(k->K);
    free(k);
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
    if (!result) {
        ERROR("malloc failure");
    }
    sprintf(result, "%0*d", digits, otp);

    assert(strlen(result)==digits);

    return result;
}

void self_test() {
    bool test_hmac = true;
    bool test_b32 = true;
    bool test_totp = true;
    bool test_bitset = true;

    if (test_hmac) {
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

    }

    if (test_b32) {
        key *k;
        k = key_from_b32("MZXW6YTB");
        assert(memcmp(k->K, (unsigned char*)"fooba", 5) == 0);
        assert(k->len == 5);
        delete_key(k);


        k = key_from_b32("GEZDGNBVGY3---asdf---TQOJQGEZDGNBVGY3TQOJQ");
        assert(k == NULL);

        k = key_from_b32("GEZDGNBVGY3");
        delete_key(k);
    }

    if (test_totp) {
        key *k;

        k = key_from_b32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

        char *totp;

        totp = generate_TOTP(k, 0x0000000000000001, 8, ALGO_SHA1);
        assert(strcmp(totp, "94287082") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x00000000023523EC, 8, ALGO_SHA1);
        assert(strcmp(totp, "07081804") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x00000000023523ED, 8, ALGO_SHA1);
        assert(strcmp(totp, "14050471") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x000000000273EF07, 8, ALGO_SHA1);
        assert(strcmp(totp, "89005924") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x0000000003F940AA, 8, ALGO_SHA1);
        assert(strcmp(totp, "69279037") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x0000000027BC86AA, 8, ALGO_SHA1);
        assert(strcmp(totp, "65353130") == 0);
        free(totp);

        delete_key(k);

        k = key_from_b32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====");
        totp = generate_TOTP(k, 0x0000000000000001, 8, ALGO_SHA256);
        assert(strcmp(totp, "46119246") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x00000000023523EC, 8, ALGO_SHA256);
        assert(strcmp(totp, "68084774") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x00000000023523ED, 8, ALGO_SHA256);
        assert(strcmp(totp, "67062674") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x000000000273EF07, 8, ALGO_SHA256);
        assert(strcmp(totp, "91819424") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x0000000003F940AA, 8, ALGO_SHA256);
        assert(strcmp(totp, "90698825") == 0);
        free(totp);

        totp = generate_TOTP(k, 0x0000000027BC86AA, 8, ALGO_SHA256);
        assert(strcmp(totp, "77737706") == 0);
        free(totp);

        delete_key(k);
        k = key_from_b32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQ"
                         "OJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY"
                         "3TQOJQGEZDGNA=");
        totp = generate_TOTP(k, 0x0000000000000001, 8, ALGO_SHA512);
        assert(strcmp(totp, "90693936") == 0);
        free(totp);
        totp = generate_TOTP(k, 0x00000000023523EC, 8, ALGO_SHA512);
        assert(strcmp(totp, "25091201") == 0);
        free(totp);
        totp = generate_TOTP(k, 0x00000000023523ED, 8, ALGO_SHA512);
        assert(strcmp(totp, "99943326") == 0);
        free(totp);
        totp = generate_TOTP(k, 0x000000000273EF07, 8, ALGO_SHA512);
        assert(strcmp(totp, "93441116") == 0);
        free(totp);
        totp = generate_TOTP(k, 0x0000000003F940AA, 8, ALGO_SHA512);
        assert(strcmp(totp, "38618901") == 0);
        free(totp);
        totp = generate_TOTP(k, 0x0000000027BC86AA, 8, ALGO_SHA512);
        assert(strcmp(totp, "47863826") == 0);
        free(totp);

        delete_key(k);
        k = key_from_b32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        totp = generate_TOTP(k, 0x0000000088888888, 6, ALGO_SHA1);
        assert(strcmp(totp, "596617") == 0);
        free(totp);
        delete_key(k);
    }

    if (test_bitset) {
        unsigned char mem[1];
        mem[0] = 0b11001001;
        assert(test_bit_int(mem[0], 0));
        assert(!test_bit_int(mem[0], 1));
        assert(!test_bit_int(mem[0], 2));
        assert(test_bit_int(mem[0], 3));
        assert(!test_bit_int(mem[0], 4));
        assert(!test_bit_int(mem[0], 5));
        assert(test_bit_int(mem[0], 6));
        assert(test_bit_int(mem[0], 7));
        set_bit(mem, 2);
        assert(test_bit_int(mem[0], 6));
        // Yes, set_bit and test_bit_int use different indexes.  Because
        // set_bit starts counting from the left, and test_bit_int
        // starts counting from the right.
    }
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
    sqlite3_finalize(stmt);
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

    sqlite3_finalize(stmt);
}

int main() {
    self_test();
    printf("Self tests all passed\n");
    sqlite3 *conn;
    sqlite3_open("tokens.db", &conn);
    uninit_database(conn);
    init_database(conn);

    /*
    char input[256];
    const char *prompt = "> ";

    printf("%s", prompt);
    while(fgets(input, sizeof(input), stdin) != NULL) {
        printf("%s", prompt);
    }
    */
    int ret = sqlite3_close(conn);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Error closing database: %s\n", sqlite3_errmsg(conn));
    }
}
