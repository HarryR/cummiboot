#ifndef CUMMIBOOT_SHA256_C_
#define CUMMIBOOT_SHA256_C_

// ------------------------------------------------------------------
// SHA256 + HMAC, for TPM session shit
// TODO: replace with intrinsic: https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c


#define SHA256_SIZE_BYTES       (32)
#define SHA256_BLOCK_SIZE_BYTES (64)

typedef struct {
    uint8_t  buf[SHA256_BLOCK_SIZE_BYTES];
    uint32_t hash[8];
    uint32_t bits[2];
    uint32_t len;
    uint32_t rfu__;
    uint32_t W[SHA256_BLOCK_SIZE_BYTES];
} sha256_context;

static const uint32_t _sha256_K[SHA256_BLOCK_SIZE_BYTES] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline __attribute__((always_inline,const))
uint8_t _sha256_shb(uint32_t x, uint32_t n) {
    return ((x >> (n & 31)) & 0xff);
} // _shb

static inline __attribute__((always_inline,const))
uint32_t _sha256_shw(uint32_t x, uint32_t n) {
    return ((x << (n & 31)) & 0xffffffff);
} // _shw

static inline __attribute__((always_inline,const))
uint32_t _sha256_r(uint32_t x, uint8_t n) {
    return ((x >> n) | _sha256_shw(x, 32 - n));
} // _r

static inline __attribute__((always_inline,const))
uint32_t _sha256_Ch(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) ^ ((~x) & z));
} // _Ch

static inline __attribute__((always_inline,const))
uint32_t _sha256_Ma(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) ^ (x & z) ^ (y & z));
} // _Ma

static inline __attribute__((always_inline,const))
uint32_t _sha256_S0(uint32_t x) {
    return (_sha256_r(x, 2) ^ _sha256_r(x, 13) ^ _sha256_r(x, 22));
} // _S0

static inline __attribute__((always_inline,const))
uint32_t _sha256_S1(uint32_t x) {
    return (_sha256_r(x, 6) ^ _sha256_r(x, 11) ^ _sha256_r(x, 25));
} // _S1

static inline __attribute__((always_inline,const))
uint32_t _sha256_G0(uint32_t x) {
    return (_sha256_r(x, 7) ^ _sha256_r(x, 18) ^ (x >> 3));
} // _G0

static inline __attribute__((always_inline,const))
uint32_t _sha256_G1(uint32_t x) {
    return (_sha256_r(x, 17) ^ _sha256_r(x, 19) ^ (x >> 10));
} // _G1

static inline __attribute__((always_inline,nonnull))
uint32_t _sha256_word(uint8_t *c) {
    return (_sha256_shw(c[0], 24) | _sha256_shw(c[1], 16) | _sha256_shw(c[2], 8) | (c[3]));
} // _word

static inline __attribute__((always_inline,nonnull))
void _sha256_addbits(sha256_context *ctx, const uint32_t n)
{
    if (ctx->bits[0] > (0xffffffff - n)) {
        ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
    }
    ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
} // _addbits

static inline __attribute__((nonnull))
void _sha256_hash_inner(sha256_context *ctx)
{
    register uint32_t a, b, c, d, e, f, g, h;
    uint32_t t[2];

    a = ctx->hash[0];
    b = ctx->hash[1];
    c = ctx->hash[2];
    d = ctx->hash[3];
    e = ctx->hash[4];
    f = ctx->hash[5];
    g = ctx->hash[6];
    h = ctx->hash[7];

    uint32_t i;
    for (i = 0; i < SHA256_BLOCK_SIZE_BYTES; i++) {
        if (i < 16) {
            ctx->W[i] = _sha256_word(&ctx->buf[_sha256_shw(i, 2)]);
        } else {
            ctx->W[i] = _sha256_G1(ctx->W[i - 2])  + ctx->W[i - 7] +
                        _sha256_G0(ctx->W[i - 15]) + ctx->W[i - 16];
        }

        t[0] = h + _sha256_S1(e) + _sha256_Ch(e, f, g) + _sha256_K[i] + ctx->W[i];
        t[1] = _sha256_S0(a) + _sha256_Ma(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t[0];
        d = c;
        c = b;
        b = a;
        a = t[0] + t[1];
    }

    ctx->hash[0] += a;
    ctx->hash[1] += b;
    ctx->hash[2] += c;
    ctx->hash[3] += d;
    ctx->hash[4] += e;
    ctx->hash[5] += f;
    ctx->hash[6] += g;
    ctx->hash[7] += h;
} // _hash_inner

static inline __attribute__((nonnull))
void sha256_init(sha256_context *ctx)
{
    ctx->bits[0] = ctx->bits[1] = ctx->len = 0;
    ctx->hash[0] = 0x6a09e667;
    ctx->hash[1] = 0xbb67ae85;
    ctx->hash[2] = 0x3c6ef372;
    ctx->hash[3] = 0xa54ff53a;
    ctx->hash[4] = 0x510e527f;
    ctx->hash[5] = 0x9b05688c;
    ctx->hash[6] = 0x1f83d9ab;
    ctx->hash[7] = 0x5be0cd19;
} // sha256_init

static inline __attribute__((nonnull))
void sha256_update(sha256_context *ctx, const void *data, unsigned long len)
{
    const uint8_t *bytes = (const uint8_t *)data;

    if (ctx->len < sizeof(ctx->buf)) {
        unsigned long i;
        for (i = 0; i < len; i++) {
            ctx->buf[ctx->len++] = bytes[i];
            if (ctx->len == sizeof(ctx->buf)) {
                _sha256_hash_inner(ctx);
                _sha256_addbits(ctx, sizeof(ctx->buf) * 8);
                ctx->len = 0;
            }
        }
    }
} // sha256_update

static inline __attribute__((nonnull))
void sha256_final(sha256_context *ctx, uint8_t *hash)
{
    register uint32_t i, j;

    j = ctx->len % sizeof(ctx->buf);
    ctx->buf[j] = 0x80;
    for (i = j + 1; i < sizeof(ctx->buf); i++) {
        ctx->buf[i] = 0x00;
    }

    if (ctx->len > 55) {
        _sha256_hash_inner(ctx);
        for (j = 0; j < sizeof(ctx->buf); j++) {
            ctx->buf[j] = 0x00;
        }
    }

    _sha256_addbits(ctx, ctx->len * 8);
    ctx->buf[63] = _sha256_shb(ctx->bits[0],  0);
    ctx->buf[62] = _sha256_shb(ctx->bits[0],  8);
    ctx->buf[61] = _sha256_shb(ctx->bits[0], 16);
    ctx->buf[60] = _sha256_shb(ctx->bits[0], 24);
    ctx->buf[59] = _sha256_shb(ctx->bits[1],  0);
    ctx->buf[58] = _sha256_shb(ctx->bits[1],  8);
    ctx->buf[57] = _sha256_shb(ctx->bits[1], 16);
    ctx->buf[56] = _sha256_shb(ctx->bits[1], 24);
    _sha256_hash_inner(ctx);

    for (i = 0, j = 24; i < 4; i++, j -= 8) {
        hash[i +  0] = _sha256_shb(ctx->hash[0], j);
        hash[i +  4] = _sha256_shb(ctx->hash[1], j);
        hash[i +  8] = _sha256_shb(ctx->hash[2], j);
        hash[i + 12] = _sha256_shb(ctx->hash[3], j);
        hash[i + 16] = _sha256_shb(ctx->hash[4], j);
        hash[i + 20] = _sha256_shb(ctx->hash[5], j);
        hash[i + 24] = _sha256_shb(ctx->hash[6], j);
        hash[i + 28] = _sha256_shb(ctx->hash[7], j);
    }
} // sha256_final

static inline __attribute__((always_inline,nonnull))
void sha256(const void *data, unsigned long len, uint8_t *hash) {
    sha256_context ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
} // sha256

#define I_PAD (0x36)
#define O_PAD (0x5C)


// ------------------------------------------------------------------


static inline __attribute__((nonnull))
void hmac_sha256 (uint8_t out[SHA256_SIZE_BYTES],
             const uint8_t *data, unsigned long data_len,
             const uint8_t *key, unsigned long key_len)
{
    sha256_context ss;
    uint8_t kh[SHA256_SIZE_BYTES];

    // If the key length is bigger than the buffer size B, apply the hash
    // function to it first and use the result instead.
    if (key_len > SHA256_BLOCK_SIZE_BYTES) {
        sha256_init (&ss);
        sha256_update (&ss, key, key_len);
        sha256_final (&ss, kh);
        key_len = SHA256_SIZE_BYTES;
        key = kh;
    }

    // (1) append zeros to the end of K to create a B byte string
    //     (e.g., if K is of length 20 bytes and B=64, then K will be appended with 44 zero bytes 0x00)
    // (2) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with ipad
    uint8_t kx[SHA256_BLOCK_SIZE_BYTES];
    unsigned long i;
    for (i = 0; i < key_len; i++) kx[i] = I_PAD ^ key[i];
    for (i = key_len; i < SHA256_BLOCK_SIZE_BYTES; i++) kx[i] = I_PAD ^ 0;

    // (3) append the stream of data 'text' to the B byte string resulting from step (2)
    // (4) apply H to the stream generated in step (3)
    sha256_init (&ss);
    sha256_update (&ss, kx, SHA256_BLOCK_SIZE_BYTES);
    sha256_update (&ss, data, data_len);
    sha256_final (&ss, out);

    // (5) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with opad
    // NOTE: The "kx" variable is reused.
    for (i = 0; i < key_len; i++) kx[i] = O_PAD ^ key[i];
    for (i = key_len; i < SHA256_BLOCK_SIZE_BYTES; i++) kx[i] = O_PAD ^ 0;

    // (6) append the H result from step (4) to the B byte string resulting from step (5)
    // (7) apply H to the stream generated in step (6) and output the result
    sha256_init (&ss);
    sha256_update (&ss, kx, SHA256_BLOCK_SIZE_BYTES);
    sha256_update (&ss, out, SHA256_SIZE_BYTES);
    sha256_final (&ss, out);
}


// ------------------------------------------------------------------

// CUMMIBOOT_SHA256_C_
#endif
