// Proof of concept: APK Signature Scheme v2 content digest, mmap + parallel SHA-256.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <omp.h>

#define CHUNK (1u << 20)
static uint32_t rd32(const uint8_t *p){ return p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24); }

int main(int argc, char **argv) {
    int fd = open(argv[1], O_RDONLY);
    struct stat st; fstat(fd, &st);
    size_t sz = st.st_size;
    const uint8_t *m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);

    // locate EOCD (scan back over max comment 64K)
    ssize_t eocd = -1;
    for (ssize_t i = sz - 22; i >= 0 && i > (ssize_t)sz - 22 - 65535; i--)
        if (rd32(m+i) == 0x06054b50) { eocd = i; break; }
    if (eocd < 0) { fprintf(stderr, "no EOCD\n"); return 1; }
    uint32_t cd_size = rd32(m + eocd + 12);
    uint32_t cd_off  = rd32(m + eocd + 16);

    // v2 digests three sections: [0,cd_off) contents, CD, EOCD (cd_off field -> signing block offset)
    uint8_t eocd_copy[22 + 65536];
    size_t eocd_len = sz - eocd;
    memcpy(eocd_copy, m + eocd, eocd_len);
    // in a real signer this is the signing-block offset; contents offset is the stand-in pre-insert
    memcpy(eocd_copy + 16, &cd_off, 4);

    struct { const uint8_t *p; size_t n; } sec[3] = {
        { m, cd_off }, { m + cd_off, cd_size }, { eocd_copy, eocd_len }
    };

    size_t total_chunks = 0;
    for (int s = 0; s < 3; s++) total_chunks += (sec[s].n + CHUNK - 1) / CHUNK;

    // flatten chunk list so OpenMP can schedule it evenly
    struct { const uint8_t *p; uint32_t n; } *chunks = malloc(total_chunks * sizeof(*chunks));
    size_t c = 0;
    for (int s = 0; s < 3; s++)
        for (size_t o = 0; o < sec[s].n; o += CHUNK) {
            size_t n = sec[s].n - o; if (n > CHUNK) n = CHUNK;
            chunks[c].p = sec[s].p + o; chunks[c].n = (uint32_t)n; c++;
        }

    uint8_t *digests = malloc(total_chunks * 32);
    double t0 = omp_get_wtime();

    #pragma omp parallel
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        #pragma omp for schedule(static)
        for (size_t i = 0; i < total_chunks; i++) {
            uint8_t pre[5] = { 0xa5 };
            memcpy(pre + 1, &chunks[i].n, 4);
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, pre, 5);
            EVP_DigestUpdate(ctx, chunks[i].p, chunks[i].n);
            unsigned int out;
            EVP_DigestFinal_ex(ctx, digests + i * 32, &out);
        }
        EVP_MD_CTX_free(ctx);
    }

    // top level: 0x5a || chunkCount(LE32) || concat(chunk digests)
    uint8_t top[32]; unsigned int outl;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t pre[5] = { 0x5a };
    uint32_t cc = (uint32_t)total_chunks; memcpy(pre + 1, &cc, 4);
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, pre, 5);
    EVP_DigestUpdate(ctx, digests, total_chunks * 32);
    EVP_DigestFinal_ex(ctx, top, &outl);
    double t1 = omp_get_wtime();

    printf("%-10s size=%.1fMB chunks=%zu threads=%d  digest=%.1f ms  (%.2f GB/s)  ",
           argv[1], sz/1048576.0, total_chunks, omp_get_max_threads(),
           (t1-t0)*1000, (sz/1073741824.0)/(t1-t0));
    for (int i = 0; i < 8; i++) printf("%02x", top[i]);
    printf("...\n");
    return 0;
}
