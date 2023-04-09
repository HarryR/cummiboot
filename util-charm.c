#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "_charm.c"
// encrypted file has 16 byte tag then random 16 byte IV appended to it
typedef struct { int fd; size_t size; uint8_t *map; } handle_t;
static inline uint8_t hexdigit( const char hex ) { return (hex <= '9') ? hex - '0' : toupper(hex) - 'A' + 10; }
static inline uint8_t hexbyte( const char *hex ) { return (hexdigit(*hex) << 4) | hexdigit(*(hex+1)); }
static inline void hexprint(const uint8_t *bytes, const size_t n) { for( size_t i = 0; i < n; i++ ) printf("%02x", bytes[i]); }
static inline void pexit(const char *msg, const int code) { perror(msg); exit(code); }
static inline void randombytes(void *buf, size_t len) { if ((size_t) syscall(SYS_getrandom, buf, (int) len, 0) != len) abort(); }
static inline void parse_hex(const char *hex_str, size_t len, uint8_t *out_bytes) {
    if( (2*len) != strlen(hex_str) ) { fprintf(stderr, "Error: need %ld hex encoded bytes\n", len); exit(__LINE__); }
    for( size_t b = 0; b < len; b++ ) out_bytes[b] = hexbyte(&hex_str[b * 2]);
}
static inline handle_t open_handle( const char *path, off_t truncate_to ) {
    struct stat sb;
    const int fd = open(path, truncate_to > 0 ? O_RDWR|O_CREAT|O_TRUNC : O_RDWR, 0644);
    if( -1 == fd || -1 == fstat(fd, &sb) ) { fprintf(stderr, "%s: ", path); pexit("error open/stat", __LINE__); }
    if( truncate_to > 0 ) {
        if( -1 == ftruncate(fd, truncate_to) ) { fprintf(stderr, "%s: ", path); pexit("error ftruncate", __LINE__); }
        sb.st_size = truncate_to;
    }
    uint8_t *map = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if( map == NULL ) { fprintf(stderr, "%s: ", path); pexit("map", __LINE__); }
    return (handle_t){fd, sb.st_size, map};
}
static inline void close_handle( const handle_t *handle ) {
    if( -1 == munmap(handle->map, handle->size) ) pexit("munmap infile error", __LINE__);
    if( -1 == close(handle->fd) ) pexit("close infile error", __LINE__);
}
static inline void charm_init( const char *key_hex, const char *nonce_str, uint32_t (*st)[XOODOO_STATE_SIZE], uint8_t (*key)[XOODOO_KEY_SIZE], uint8_t (*iv)[XOODOO_IV_SIZE], int rand_iv ) {    
    if( NULL != key_hex ) parse_hex(key_hex, XOODOO_KEY_SIZE, *key); else randombytes(key, XOODOO_KEY_SIZE);
    if( NULL != nonce_str ) parse_hex(nonce_str, XOODOO_IV_SIZE, *iv); else if (rand_iv ) randombytes(iv, XOODOO_IV_SIZE);
    uc_state_init(*st, *key, *iv);
}
static inline void main_hash( const char *infile, const char *nonce_str ) {
    const handle_t in = open_handle(infile, 0);
    uint32_t st[XOODOO_STATE_SIZE];
    uint8_t key[XOODOO_KEY_SIZE], iv[XOODOO_IV_SIZE], out_hash[XOODOO_DIGEST_SIZE];
    charm_init(NULL, nonce_str, &st, &key, &iv, 1);
    uc_hash(st, out_hash, in.map, in.size);
    hexprint(out_hash, XOODOO_DIGEST_SIZE); printf("\n");
    close_handle(&in);
    exit(0);
}
static inline void main_encdec(const int is_encrypt, const char *infile, const char *outfile, const char *key_hex, const char *nonce_str) {
    uint32_t st[XOODOO_STATE_SIZE];
    uint8_t key[XOODOO_KEY_SIZE], iv[XOODOO_IV_SIZE];
    const handle_t in = open_handle(infile, 0);
    handle_t out = open_handle(outfile, in.size + (is_encrypt ? (XOODOO_TAG_SIZE + XOODOO_IV_SIZE) : 0));
    memcpy(out.map, in.map, in.size);
    if( ! is_encrypt ) memcpy(iv, in.map+(in.size-XOODOO_IV_SIZE), XOODOO_IV_SIZE);
    charm_init(key_hex, nonce_str, &st, &key, &iv, is_encrypt);
    if( is_encrypt ) {
        hexprint(key, XOODOO_KEY_SIZE); printf("\n");
        uc_encrypt(st, out.map, in.size, out.map+in.size);
        memcpy(out.map+(in.size+XOODOO_TAG_SIZE), iv, XOODOO_IV_SIZE);
    } else {
        if( in.size < (1+XOODOO_TAG_SIZE+XOODOO_IV_SIZE) ) { fprintf(stderr, "Error: file too small, missing tag or IV\n"); exit(1); }
        if( 0 != uc_decrypt(st, out.map, in.size-XOODOO_TAG_SIZE-XOODOO_IV_SIZE, out.map+(in.size-XOODOO_TAG_SIZE-XOODOO_IV_SIZE), XOODOO_TAG_SIZE) )
        { fprintf(stderr, "Error: decrypt failed! Mismatched tag\n"); exit(1); }
    }
    close_handle(&in);
    if( ! is_encrypt && -1 == ftruncate(out.fd, in.size-XOODOO_TAG_SIZE-XOODOO_IV_SIZE)) pexit("ftruncate outfile error", __LINE__);
    close_handle(&out);
    exit(0);
}
int main( int argc, char **argv ) {
    if( argc >= 4 && argc <= 6 ) {
        const int is_encrypt = (0 == strcmp(argv[1], "encrypt"));
        if( is_encrypt || (0 == strcmp(argv[1], "decrypt")) ) main_encdec(is_encrypt, argv[2], argv[3], argv[4], 6 == argc ? argv[5] : NULL);
    }
    if( (3 == argc || 4 == argc) && 0 == strcmp(argv[1], "hash") ) main_hash(argv[2], 4 == argc ? argv[3] : NULL);
    fprintf(stderr, "Usage: %s hash <infile> [nonce]\n", argv[0]);
    fprintf(stderr, "   or...\n");
    fprintf(stderr, "Usage: %s encrypt|decrypt <infile> <outfile> [<256bit-key-hex> [128bit-nonce-hex]]\n", argv[0]);
    fprintf(stderr, "  e.g. %s encrypt %s %s.encrypted `od -vAn -N32 -tx1 /dev/urandom | tr -cd '[a-f0-9]'`\n", argv[0], argv[0], argv[0]);
    return __LINE__;
}
