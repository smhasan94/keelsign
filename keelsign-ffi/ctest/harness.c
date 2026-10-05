/*
 * C99 test harness for libkeelsign.a (SHA-60). Driven by
 * tools/repo-checks/tests/ffi.rs; see docs/ffi.md for the manual smoke test.
 *
 *   harness verify POLICY IMAGE [ALG:KEYFILE ...]
 *   harness digest IMAGE
 *   harness abuse IMAGE LMS_KEYFILE
 *
 * POLICY is classical_only, pq_only, hybrid or a number; ALG is mldsa44, mldsa65, lms,
 * ed25519 or a number. KEYFILE holds the raw public key bytes. Each command prints one
 * line starting with "status=" and exits 0 whenever the library was called; usage and
 * I/O errors exit 2.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keelsign.h"

#define MAX_KEYS 32

/* Reads a whole file into an exactly sized heap buffer (so a sanitizer sees any read
 * past its end). A zero-length file gives a 1-byte buffer and *len 0. */
static uint8_t *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  long size;
  uint8_t *buf;
  if (f == NULL) {
    fprintf(stderr, "harness: cannot open %s\n", path);
    exit(2);
  }
  if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fprintf(stderr, "harness: cannot size %s\n", path);
    exit(2);
  }
  buf = (uint8_t *)malloc(size > 0 ? (size_t)size : 1u);
  if (buf == NULL) {
    fprintf(stderr, "harness: out of memory\n");
    exit(2);
  }
  if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
    fprintf(stderr, "harness: cannot read %s\n", path);
    exit(2);
  }
  fclose(f);
  *len = (size_t)size;
  return buf;
}

static uint32_t parse_number(const char *text) {
  char *end = NULL;
  unsigned long value = strtoul(text, &end, 0);
  if (end == text || *end != '\0' || value > 0xFFFFFFFFul) {
    fprintf(stderr, "harness: bad number %s\n", text);
    exit(2);
  }
  return (uint32_t)value;
}

static keelsign_policy_t parse_policy(const char *text) {
  if (strcmp(text, "classical_only") == 0) return KEELSIGN_POLICY_CLASSICAL_ONLY;
  if (strcmp(text, "pq_only") == 0) return KEELSIGN_POLICY_PQ_ONLY;
  if (strcmp(text, "hybrid") == 0) return KEELSIGN_POLICY_HYBRID;
  return parse_number(text);
}

static keelsign_alg_t parse_alg(const char *text) {
  if (strcmp(text, "mldsa44") == 0) return KEELSIGN_ALG_MLDSA44;
  if (strcmp(text, "mldsa65") == 0) return KEELSIGN_ALG_MLDSA65;
  if (strcmp(text, "lms") == 0) return KEELSIGN_ALG_LMS_HSS;
  if (strcmp(text, "ed25519") == 0) return KEELSIGN_ALG_ED25519;
  return parse_number(text);
}

static void print_hex(const uint8_t *bytes, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) printf("%02x", bytes[i]);
}

static int cmd_verify(int argc, char **argv) {
  keelsign_key_t keys[MAX_KEYS];
  uint8_t *key_bytes[MAX_KEYS];
  keelsign_result_t out;
  keelsign_status_t status;
  size_t image_len, n_keys = 0, i;
  keelsign_policy_t policy;
  uint8_t *image;
  if (argc < 4 || argc - 4 > MAX_KEYS) {
    fprintf(stderr, "usage: harness verify POLICY IMAGE [ALG:KEYFILE ...]\n");
    return 2;
  }
  policy = parse_policy(argv[2]);
  image = slurp(argv[3], &image_len);
  for (i = 4; i < (size_t)argc; i++) {
    char *colon = strchr(argv[i], ':');
    if (colon == NULL) {
      fprintf(stderr, "harness: key %s is not ALG:KEYFILE\n", argv[i]);
      return 2;
    }
    *colon = '\0';
    keys[n_keys].alg = parse_alg(argv[i]);
    key_bytes[n_keys] = slurp(colon + 1, &keys[n_keys].key_len);
    keys[n_keys].key = key_bytes[n_keys];
    n_keys++;
  }
  memset(&out, 0xA5, sizeof out);
  status = keelsign_verify(image, image_len, n_keys > 0 ? keys : NULL, n_keys, policy, &out);
  printf("status=%d", (int)status);
  if (status == KEELSIGN_OK) {
    printf(" version=%u.%u.%u+%lu", (unsigned)out.major, (unsigned)out.minor,
           (unsigned)out.revision, (unsigned long)out.build_num);
    printf(" has_security_counter=%u security_counter=%lu image_len=%lu digest=",
           (unsigned)out.has_security_counter, (unsigned long)out.security_counter,
           (unsigned long)out.image_len);
    print_hex(out.digest, sizeof out.digest);
    printf(" pq_key_index=%lu ed25519_key_index=%lu", (unsigned long)out.pq_key_index,
           (unsigned long)out.ed25519_key_index);
  }
  printf("\n");
  for (i = 0; i < n_keys; i++) free(key_bytes[i]);
  free(image);
  return 0;
}

static int cmd_digest(int argc, char **argv) {
  uint8_t digest[32];
  size_t image_len;
  uint8_t *image;
  keelsign_status_t status;
  if (argc != 3) {
    fprintf(stderr, "usage: harness digest IMAGE\n");
    return 2;
  }
  image = slurp(argv[2], &image_len);
  memset(digest, 0xA5, sizeof digest);
  status = keelsign_digest(image, image_len, digest);
  printf("status=%d", (int)status);
  if (status == KEELSIGN_OK) {
    printf(" digest=");
    print_hex(digest, sizeof digest);
  }
  printf("\n");
  free(image);
  return 0;
}

/* NULL, zero-length and malformed arguments, each a separate call: prints the nine
 * statuses in order. */
static int cmd_abuse(int argc, char **argv) {
  keelsign_key_t key, many[KEELSIGN_MAX_PQ_KEYS + 1], pair[2], bad;
  keelsign_status_t s[9];
  size_t image_len, key_len, i;
  uint8_t *image, *key_buf;
  if (argc != 4) {
    fprintf(stderr, "usage: harness abuse IMAGE LMS_KEYFILE\n");
    return 2;
  }
  image = slurp(argv[2], &image_len);
  key_buf = slurp(argv[3], &key_len);
  key.alg = KEELSIGN_ALG_LMS_HSS;
  key.key = key_buf;
  key.key_len = key_len;
  /* 1: NULL image. */
  s[0] = keelsign_verify(NULL, image_len, &key, 1, KEELSIGN_POLICY_PQ_ONLY, NULL);
  /* 1: NULL keys with n_keys > 0. */
  s[1] = keelsign_verify(image, image_len, NULL, 1, KEELSIGN_POLICY_PQ_ONLY, NULL);
  /* 1: NULL digest output. */
  s[2] = keelsign_digest(image, image_len, NULL);
  /* 31: zero-length image. */
  s[3] = keelsign_verify(image, 0, &key, 1, KEELSIGN_POLICY_PQ_ONLY, NULL);
  /* 3: unknown policy. */
  s[4] = keelsign_verify(image, image_len, &key, 1, 7u, NULL);
  /* 4: unknown algorithm. */
  bad = key;
  bad.alg = 9u;
  s[5] = keelsign_verify(image, image_len, &bad, 1, KEELSIGN_POLICY_PQ_ONLY, NULL);
  /* 5: one key more than KEELSIGN_MAX_PQ_KEYS. */
  for (i = 0; i < KEELSIGN_MAX_PQ_KEYS + 1; i++) many[i] = key;
  s[6] = keelsign_verify(image, image_len, many, KEELSIGN_MAX_PQ_KEYS + 1,
                         KEELSIGN_POLICY_PQ_ONLY, NULL);
  /* 6: the same key twice. */
  pair[0] = key;
  pair[1] = key;
  s[7] = keelsign_verify(image, image_len, pair, 2, KEELSIGN_POLICY_PQ_ONLY, NULL);
  /* 7: the key one byte short. */
  bad = key;
  bad.key_len = key_len - 1;
  s[8] = keelsign_verify(image, image_len, &bad, 1, KEELSIGN_POLICY_PQ_ONLY, NULL);
  printf("status=");
  for (i = 0; i < 9; i++) printf(i == 0 ? "%d" : ",%d", (int)s[i]);
  printf("\n");
  free(key_buf);
  free(image);
  return 0;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "verify") == 0) return cmd_verify(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "digest") == 0) return cmd_digest(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "abuse") == 0) return cmd_abuse(argc, argv);
  fprintf(stderr,
          "usage: harness verify POLICY IMAGE [ALG:KEYFILE ...]\n"
          "       harness digest IMAGE\n"
          "       harness abuse IMAGE LMS_KEYFILE\n");
  return 2;
}
