/* Copyright (c) 2012-2020 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file hash-questions.c
 * @brief DNS question section hashing for cache poisoning prevention
 * 
 * DETAILED PURPOSE:
 * This module implements SHA-256 hashing of DNS question sections to provide
 * cryptographic verification of DNS responses, preventing cache poisoning attacks
 * and detecting query retransmissions. The implementation computes a digest over
 * the decoded question name (with case normalization per DNS rules), question type,
 * and question class. By hashing the decoded name rather than raw bytes, the
 * implementation correctly handles DNS name compression variations that may occur
 * between queries and responses.
 * 
 * The module provides two alternative implementations selected at compile time:
 * when HAVE_DNSSEC or HAVE_CRYPTOHASH is defined, the Nettle cryptographic library
 * is used for SHA-256 operations; otherwise, a standalone public-domain SHA-256
 * implementation is included to avoid external dependencies.
 * 
 * KEY RESPONSIBILITIES:
 * - hash_questions_init(): Initialize SHA-256 hashing context at daemon startup
 * - hash_questions(): Compute SHA-256 digest of all questions in DNS packet
 * - SHA-256 implementation: Provide standalone cryptographic hash when Nettle unavailable
 * 
 * DEPENDENCIES:
 * - dnsmasq.h: Core type definitions including struct dns_header
 * - extract_name(): DNS name decompression (from rfc1035.c)
 * - CHECK_LEN(): Packet boundary validation macro
 * - Nettle library (optional): hash_find(), struct nettle_hash (when HAVE_DNSSEC/HAVE_CRYPTOHASH)
 * - safe_malloc(): Memory allocation wrapper (from util.c)
 * 
 * DATA STRUCTURES:
 * - SHA256_CTX (lines 83-88): SHA-256 context for standalone implementation
 * - struct nettle_hash: External Nettle hash interface (when using Nettle)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC: When defined, uses Nettle crypto library for SHA-256 operations
 * - HAVE_CRYPTOHASH: Alternative flag to enable Nettle crypto library usage
 * - Neither defined: Uses standalone public-domain SHA-256 implementation
 * 
 * THREADING/CONCURRENCY:
 * This module is designed for single-process event-driven architecture.
 * The hash_questions() function is re-entrant when using standalone implementation
 * (context on stack). When using Nettle, module-level context requires external
 * synchronization, though dnsmasq's single-threaded model makes this unnecessary.
 * 
 * RFC COMPLIANCE:
 * - DNS name canonicalization per RFC 1035 (case-insensitive comparison)
 * - Cryptographic verification supports DNS security best practices
 * - SHA-256 algorithm per FIPS PUB 180-4
 * 
 * SECURITY CONSIDERATIONS:
 * This module is critical for DNS cache poisoning prevention. The SHA-256 hash
 * provides collision resistance to detect unauthorized response substitution.
 * Case normalization ensures hash consistency across different name encodings.
 * 
 * @copyright Copyright (c) 2012-2020 Simon Kelley
 * @license GPL-2.0-or-later
 */

/* Hash the question section. This is used to safely detect query 
   retransmission and to detect answers to questions we didn't ask, which 
   might be poisoning attacks. Note that we decode the name rather 
   than CRC the raw bytes, since replies might be compressed differently. 
   We ignore case in the names for the same reason. 

   The hash used is SHA-256. If we're building with DNSSEC support,
   we use the Nettle cypto library. If not, we prefer not to
   add a dependency on Nettle, and use a stand-alone implementaion. 
*/

#include "dnsmasq.h"

#if defined(HAVE_DNSSEC) || defined(HAVE_CRYPTOHASH)

static const struct nettle_hash *hash;
static void *ctx;
static unsigned char *digest;

/**
 * @brief Initialize SHA-256 hashing context for DNS question verification
 * 
 * @detailed
 * Initializes the Nettle cryptographic library SHA-256 hash context used for
 * computing DNS question section digests. This function is called once during
 * daemon startup to allocate and prepare the hash context. The implementation
 * locates the SHA-256 hash algorithm via Nettle's hash_find() interface and
 * allocates memory for the hash context and digest buffer based on the
 * algorithm's requirements (32 bytes for SHA-256).
 * 
 * @note This version is compiled when HAVE_DNSSEC or HAVE_CRYPTOHASH is defined
 * @note Context is stored in module-level static variables for reuse across calls
 * @warning Terminates daemon with die() if SHA-256 algorithm cannot be located
 * 
 * @see hash_questions() for usage of initialized context
 * @see hash_find() in crypto.c for algorithm lookup mechanism
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization
 * hash_questions_init();
 * // Context now ready for hash_questions() calls
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Allocates memory for hash context (typically 32 bytes for SHA-256)
 * - Allocates memory for digest buffer (32 bytes for SHA-256)
 * - Stores pointers in module-level static variables
 * - Terminates process if SHA-256 unavailable
 * 
 * THREAD SAFETY:
 * Not thread-safe due to module-level static variable initialization.
 * Must be called before any hash_questions() calls. Safe in dnsmasq's
 * single-threaded event-driven architecture.
 */
void hash_questions_init(void)
{
  if (!(hash = hash_find("sha256")))
    die(_("Failed to create SHA-256 hash object"), NULL, EC_MISC);

  ctx = safe_malloc(hash->context_size);
  digest = safe_malloc(hash->digest_size);
}

/**
 * @brief Compute SHA-256 digest of DNS question section for response verification
 * 
 * @detailed
 * Computes a cryptographic SHA-256 hash over all questions in a DNS packet to
 * enable detection of cache poisoning attacks and query retransmissions. The
 * function iterates through all questions in the DNS header's question section,
 * extracts and canonicalizes each question name (converting to lowercase per
 * RFC 1035 case-insensitivity rules), and includes the question type and class
 * in the hash computation. This approach ensures the hash remains consistent
 * despite DNS name compression variations between queries and responses.
 * 
 * @param header Pointer to DNS packet header containing questions to hash
 * @param plen Total length of DNS packet in bytes for boundary checking
 * @param name Buffer for temporary storage of extracted question names (MAXDNAME size)
 * 
 * @return Pointer to 32-byte SHA-256 digest on success
 * @retval NULL if packet is malformed or truncated (extract_name failure or boundary violation)
 * 
 * @note Uses Nettle crypto library implementation (HAVE_DNSSEC/HAVE_CRYPTOHASH build)
 * @note Digest pointer remains valid until next hash_questions() call (points to static buffer)
 * @note Case normalization converts A-Z to a-z per DNS case-insensitive name comparison rules
 * @warning Returned pointer is to module-level static buffer, not thread-safe
 * @warning Does not validate header->qdcount range; relies on extract_name() validation
 * 
 * @see hash_questions_init() for initialization requirements
 * @see extract_name() in rfc1035.c for DNS name decompression
 * @see CHECK_LEN() macro for packet boundary validation
 * @see forward.c for usage in query ID verification
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * char name[MAXDNAME];
 * unsigned char *digest = hash_questions(header, packet_len, name);
 * if (digest)
 *   memcmp(digest, expected_digest, 32); // Verify 32-byte digest
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1035 Section 3.1: Domain name case-insensitive comparison
 * - DNS Security: Cryptographic verification of question section integrity
 * - FIPS PUB 180-4: SHA-256 cryptographic hash algorithm
 * 
 * SIDE EFFECTS:
 * - Modifies name buffer with extracted question names (temporary)
 * - Overwrites module-level digest buffer with new hash value
 * - Advances internal pointer through packet (local variable, no persistent effect)
 * 
 * THREAD SAFETY:
 * Not thread-safe due to shared module-level digest buffer. Safe in dnsmasq's
 * single-process event-driven model where only one query is processed at a time.
 */
unsigned char *hash_questions(struct dns_header *header, size_t plen, char *name)
{
  int q;
  unsigned char *p = (unsigned char *)(header+1);

  hash->init(ctx);

  for (q = ntohs(header->qdcount); q != 0; q--) 
    {
      char *cp, c;

      if (!extract_name(header, plen, &p, name, 1, 4))
	return NULL; /* bad packet */

      for (cp = name; (c = *cp); cp++)
	 if (c >= 'A' && c <= 'Z')
	   *cp += 'a' - 'A';

      hash->update(ctx, cp - name, (unsigned char *)name);
      /* CRC the class and type as well */
      hash->update(ctx, 4, p);

      p += 4;
      if (!CHECK_LEN(header, p, plen, 0))
	return NULL; /* bad packet */
    }
  
  hash->digest(ctx, hash->digest_size, digest);
  return digest;
}

#else /* HAVE_DNSSEC  || HAVE_CRYPTOHASH */

/**
 * @def SHA256_BLOCK_SIZE
 * @brief SHA-256 digest output size in bytes
 * 
 * Defines the fixed output size of SHA-256 cryptographic hash algorithm.
 * SHA-256 always produces a 32-byte (256-bit) digest regardless of input size.
 * This constant is used for digest buffer allocation and validation.
 */
#define SHA256_BLOCK_SIZE 32            /* SHA256 outputs a 32 byte digest */

typedef unsigned char BYTE;             /* 8-bit byte */
typedef unsigned int  WORD;             /* 32-bit word, change to "long" for 16-bit machines */

/**
 * @struct SHA256_CTX
 * @brief SHA-256 hashing context for standalone implementation
 * 
 * @detailed
 * Maintains the internal state for incremental SHA-256 hash computation.
 * The structure holds the partial data buffer, current hash state, and
 * bit count required by the SHA-256 algorithm as specified in FIPS PUB 180-4.
 * This context allows hashing of data in multiple update calls before
 * finalizing the digest.
 * 
 * LIFECYCLE:
 * 1. Initialize with sha256_init() - sets initial hash values per FIPS 180-4
 * 2. Update with sha256_update() - process data in chunks (can be called multiple times)
 * 3. Finalize with sha256_final() - apply padding and extract final digest
 * 
 * MEMORY LAYOUT:
 * - data[64]: Input buffer for block processing (512-bit SHA-256 block size)
 * - datalen: Current number of bytes in data buffer (0-63)
 * - bitlen: Total number of bits processed (for final padding)
 * - state[8]: Eight 32-bit SHA-256 state words (H0-H7 per FIPS 180-4)
 * 
 * @var data 64-byte buffer accumulating input data until full block available
 * @var datalen Number of bytes currently stored in data buffer (0 to 63)
 * @var bitlen Total message length in bits processed so far (for padding)
 * @var state Eight 32-bit words representing current SHA-256 hash state
 * 
 * @note Structure size is approximately 104 bytes on 32-bit systems
 * @note Context can be allocated on stack (as done in hash_questions)
 */
typedef struct {
  BYTE data[64];
  WORD datalen;
  unsigned long long bitlen;
  WORD state[8];
} SHA256_CTX;

static void sha256_init(SHA256_CTX *ctx);
static void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
static void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

/**
 * @brief Initialize SHA-256 hashing (no-op for standalone implementation)
 * 
 * @detailed
 * Stub initialization function for standalone SHA-256 implementation. Unlike
 * the Nettle version, the standalone implementation allocates SHA256_CTX on
 * the stack in hash_questions(), requiring no global initialization. This
 * function is provided to maintain API compatibility with the Nettle version.
 * 
 * @note This version is compiled when neither HAVE_DNSSEC nor HAVE_CRYPTOHASH is defined
 * @note Function intentionally empty - context is stack-allocated per call
 * 
 * @see hash_questions() for actual SHA-256 context usage
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization (no effect for standalone)
 * hash_questions_init();
 * @endcode
 * 
 * SIDE EFFECTS:
 * None - function is a no-op for standalone implementation.
 * 
 * THREAD SAFETY:
 * Fully thread-safe (does nothing). Standalone implementation uses
 * stack-allocated contexts, avoiding shared state.
 */
void hash_questions_init(void)
{
}

/**
 * @brief Compute SHA-256 digest of DNS question section using standalone implementation
 * 
 * @detailed
 * Computes a cryptographic SHA-256 hash over all questions in a DNS packet using
 * a standalone public-domain SHA-256 implementation (not requiring Nettle library).
 * Allocates SHA256_CTX on stack for full thread safety. Iterates through all
 * questions in the DNS header's question section, extracts and canonicalizes each
 * question name (converting to lowercase per RFC 1035 case-insensitivity), and
 * includes the question type and class in the hash computation. The approach
 * ensures hash consistency despite DNS name compression variations.
 * 
 * @param header Pointer to DNS packet header containing questions to hash
 * @param plen Total length of DNS packet in bytes for boundary checking
 * @param name Buffer for temporary storage of extracted question names (MAXDNAME size)
 * 
 * @return Pointer to 32-byte SHA-256 digest on success
 * @retval NULL if packet is malformed or truncated (extract_name failure or boundary violation)
 * 
 * @note Uses standalone SHA-256 implementation (neither HAVE_DNSSEC nor HAVE_CRYPTOHASH defined)
 * @note Digest pointer points to function-level static buffer (valid until next call)
 * @note Case normalization converts A-Z to a-z per DNS case-insensitive comparison
 * @warning Returned pointer is to function-level static buffer, not thread-safe across calls
 * @warning Does not validate header->qdcount range; relies on extract_name() validation
 * 
 * @see hash_questions_init() for API compatibility (no-op for standalone)
 * @see extract_name() in rfc1035.c for DNS name decompression
 * @see CHECK_LEN() macro for packet boundary validation
 * @see sha256_init(), sha256_update(), sha256_final() for SHA-256 implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * char name[MAXDNAME];
 * unsigned char *digest = hash_questions(header, packet_len, name);
 * if (digest)
 *   // Compare 32-byte digest with expected value
 *   if (memcmp(digest, stored_digest, SHA256_BLOCK_SIZE) == 0)
 *     printf("Question section verified\n");
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1035 Section 3.1: Domain name case-insensitive comparison
 * - DNS Security: Cryptographic verification of question section integrity
 * - FIPS PUB 180-4: SHA-256 cryptographic hash algorithm specification
 * 
 * SIDE EFFECTS:
 * - Modifies name buffer with extracted question names (temporary)
 * - Overwrites function-level static digest buffer with new hash value
 * - Stack-allocates SHA256_CTX context (approximately 104 bytes)
 * 
 * THREAD SAFETY:
 * Not thread-safe due to function-level static digest buffer. Safe in dnsmasq's
 * single-process event-driven model. SHA256_CTX on stack provides isolation
 * between simultaneous calls in multi-threaded environment (though not used in dnsmasq).
 */
unsigned char *hash_questions(struct dns_header *header, size_t plen, char *name)
{
  int q;
  unsigned char *p = (unsigned char *)(header+1);
  SHA256_CTX ctx;
  static BYTE digest[SHA256_BLOCK_SIZE];
  
  sha256_init(&ctx);
    
  for (q = ntohs(header->qdcount); q != 0; q--) 
    {
      char *cp, c;

      if (!extract_name(header, plen, &p, name, 1, 4))
	return NULL; /* bad packet */

      for (cp = name; (c = *cp); cp++)
	 if (c >= 'A' && c <= 'Z')
	   *cp += 'a' - 'A';

      sha256_update(&ctx, (BYTE *)name, cp - name);
      /* CRC the class and type as well */
      sha256_update(&ctx, (BYTE *)p, 4);

      p += 4;
      if (!CHECK_LEN(header, p, plen, 0))
	return NULL; /* bad packet */
    }
  
  sha256_final(&ctx, digest);
  return (unsigned char *)digest;
}

/* Code from here onwards comes from https://github.com/B-Con/crypto-algorithms
   and was written by Brad Conte (brad@bradconte.com), to whom all credit is given.

   This code is in the public domain, and the copyright notice at the head of this 
   file does not apply to it.
*/


/****************************** MACROS ******************************/

/**
 * @def ROTLEFT(a,b)
 * @brief Rotate 32-bit word left by specified number of bits
 * 
 * Performs circular left rotation of 32-bit value, used in SHA-256 algorithm.
 * Bits shifted off the left end wrap around to the right end.
 * 
 * @note Used in SHA-256 message schedule and compression function
 */
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))

/**
 * @def ROTRIGHT(a,b)
 * @brief Rotate 32-bit word right by specified number of bits
 * 
 * Performs circular right rotation of 32-bit value, fundamental operation in SHA-256.
 * Bits shifted off the right end wrap around to the left end. Used extensively
 * in SHA-256 logical functions (EP0, EP1, SIG0, SIG1).
 * 
 * @note Core building block for all SHA-256 logical functions per FIPS 180-4
 */
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

/**
 * @def CH(x,y,z)
 * @brief SHA-256 Choose function: (x AND y) XOR (NOT x AND z)
 * 
 * Implements SHA-256 Ch(x,y,z) logical function per FIPS PUB 180-4 Section 4.1.2.
 * The function "chooses" bits from y or z based on corresponding bit in x:
 * if x bit is 1, result bit comes from y; if x bit is 0, result comes from z.
 * 
 * @note Used in SHA-256 compression function main loop
 */
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))

/**
 * @def MAJ(x,y,z)
 * @brief SHA-256 Majority function: (x AND y) XOR (x AND z) XOR (y AND z)
 * 
 * Implements SHA-256 Maj(x,y,z) logical function per FIPS PUB 180-4 Section 4.1.2.
 * Returns 1 if majority of input bits are 1, otherwise returns 0. Equivalent to
 * bitwise majority vote across three input words.
 * 
 * @note Used in SHA-256 compression function main loop
 */
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/**
 * @def EP0(x)
 * @brief SHA-256 Σ₀ (Sigma-0) function: ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)
 * 
 * Implements SHA-256 Σ₀(x) function per FIPS PUB 180-4 Section 4.1.2.
 * Combines three different right rotations of input word. Used in compression
 * function to compute T2 temporary word.
 * 
 * @note Capital sigma function (uppercase EP) used in compression function
 */
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))

/**
 * @def EP1(x)
 * @brief SHA-256 Σ₁ (Sigma-1) function: ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)
 * 
 * Implements SHA-256 Σ₁(x) function per FIPS PUB 180-4 Section 4.1.2.
 * Combines three different right rotations of input word. Used in compression
 * function to compute T1 temporary word.
 * 
 * @note Capital sigma function (uppercase EP) used in compression function
 */
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))

/**
 * @def SIG0(x)
 * @brief SHA-256 σ₀ (sigma-0) function: ROTR⁷(x) XOR ROTR¹⁸(x) XOR SHR³(x)
 * 
 * Implements SHA-256 σ₀(x) function per FIPS PUB 180-4 Section 4.1.2.
 * Combines two right rotations and one right shift. Used in message schedule
 * to extend 16-word input block to 64-word schedule.
 * 
 * @note Lowercase sigma function (lowercase SIG) used in message schedule
 * @note Final operation is shift (>>) not rotation, discarding shifted-out bits
 */
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))

/**
 * @def SIG1(x)
 * @brief SHA-256 σ₁ (sigma-1) function: ROTR¹⁷(x) XOR ROTR¹⁹(x) XOR SHR¹⁰(x)
 * 
 * Implements SHA-256 σ₁(x) function per FIPS PUB 180-4 Section 4.1.2.
 * Combines two right rotations and one right shift. Used in message schedule
 * to extend 16-word input block to 64-word schedule.
 * 
 * @note Lowercase sigma function (lowercase SIG) used in message schedule
 * @note Final operation is shift (>>) not rotation, discarding shifted-out bits
 */
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
/**
 * @brief SHA-256 round constants K[0..63] per FIPS PUB 180-4
 * 
 * 64 constant 32-bit words used in SHA-256 compression function, derived from
 * the first 32 bits of the fractional parts of the cube roots of the first
 * 64 prime numbers. These constants provide cryptographic strength by introducing
 * non-linearity into the hash computation.
 * 
 * @note Values are specified in FIPS PUB 180-4 Section 4.2.2
 * @note Constants are identical for all SHA-256 operations (not context-dependent)
 */
static const WORD k[64] = {
			   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
			   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
			   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
			   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
			   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
			   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
			   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
			   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
/**
 * @brief Perform SHA-256 compression function on single 512-bit block
 * 
 * @detailed
 * Implements the core SHA-256 compression function as specified in FIPS PUB 180-4
 * Section 6.2.2. Processes a single 512-bit (64-byte) message block to update
 * the hash state. The function expands the 16-word message block into a 64-word
 * message schedule using SIG0 and SIG1 functions, then performs 64 rounds of
 * operations using the Ch, Maj, EP0, and EP1 logical functions combined with
 * the round constants. The resulting values are added to the previous state to
 * produce the updated hash state.
 * 
 * @param ctx Pointer to SHA256_CTX containing current hash state to update
 * @param data Pointer to 64-byte (512-bit) message block to process
 * 
 * @note This is the computational core of SHA-256, called once per 512-bit block
 * @note Modifies ctx->state[0..7] by adding computed values to previous state
 * @note Message schedule expansion uses big-endian byte ordering
 * @warning Assumes data points to exactly 64 bytes of valid memory
 * 
 * @see sha256_update() which calls this function when buffer fills
 * @see sha256_final() which calls this function for final padded block
 * @see FIPS PUB 180-4 Section 6.2.2 for algorithm specification
 * 
 * EXAMPLE USAGE:
 * @code
 * SHA256_CTX ctx;
 * sha256_init(&ctx);
 * BYTE block[64] = { ... }; // 512-bit message block
 * sha256_transform(&ctx, block); // Process one block
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - FIPS PUB 180-4 Section 6.2.2: SHA-256 compression function specification
 * - Implements message schedule (W[0..63]) per Section 6.2.2 step 1
 * - Implements 64-round main loop per Section 6.2.2 step 2
 * - Computes intermediate hash value per Section 6.2.2 step 3
 * 
 * SIDE EFFECTS:
 * Updates ctx->state[0..7] with new hash state values by adding results
 * of compression function to previous state (modulo 2^32).
 * 
 * THREAD SAFETY:
 * Re-entrant if different ctx pointers used. Not thread-safe if same ctx
 * accessed concurrently. Caller must provide synchronization if needed.
 */
static void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
  WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
  
  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
  for ( ; i < 64; ++i)
    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i)
    {
      t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
      t2 = EP0(a) + MAJ(a,b,c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
  
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

/**
 * @brief Initialize SHA-256 context with standard initial hash values
 * 
 * @detailed
 * Initializes SHA256_CTX structure with the standard SHA-256 initial hash values
 * (H[0..7]) as specified in FIPS PUB 180-4 Section 5.3.3. These initial values
 * are the first 32 bits of the fractional parts of the square roots of the first
 * eight prime numbers (2, 3, 5, 7, 11, 13, 17, 19). Also initializes the data
 * buffer length counter and total bit length to zero in preparation for accepting
 * message data via sha256_update().
 * 
 * @param ctx Pointer to SHA256_CTX structure to initialize
 * 
 * @note Must be called before any sha256_update() or sha256_final() operations
 * @note Initial hash values are cryptographic constants, identical for all SHA-256 operations
 * @warning ctx must point to valid SHA256_CTX memory (typically stack-allocated)
 * 
 * @see sha256_update() for adding message data after initialization
 * @see sha256_final() for completing hash computation
 * @see FIPS PUB 180-4 Section 5.3.3 for initial hash value specification
 * 
 * EXAMPLE USAGE:
 * @code
 * SHA256_CTX ctx;
 * sha256_init(&ctx);
 * sha256_update(&ctx, (BYTE*)"message", 7);
 * BYTE digest[32];
 * sha256_final(&ctx, digest);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - FIPS PUB 180-4 Section 5.3.3: Initial hash value H(0) specification
 * - H[0] = 0x6a09e667, H[1] = 0xbb67ae85, H[2] = 0x3c6ef372, H[3] = 0xa54ff53a
 * - H[4] = 0x510e527f, H[5] = 0x9b05688c, H[6] = 0x1f83d9ab, H[7] = 0x5be0cd19
 * 
 * SIDE EFFECTS:
 * - Sets ctx->datalen to 0 (empty buffer)
 * - Sets ctx->bitlen to 0 (no bits processed yet)
 * - Sets ctx->state[0..7] to standard SHA-256 initial hash values
 * 
 * THREAD SAFETY:
 * Re-entrant and thread-safe. Each call operates on independent context.
 * Safe to call concurrently from multiple threads with different ctx pointers.
 */
static void sha256_init(SHA256_CTX *ctx)
{
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

/**
 * @brief Add message data to SHA-256 hash computation
 * 
 * @detailed
 * Incrementally adds message data to the SHA-256 hash computation. Accumulates
 * input bytes into the context's 64-byte buffer until a complete 512-bit block
 * is available, then processes the block via sha256_transform(). This allows
 * hashing arbitrarily large messages in multiple calls without requiring the
 * entire message in memory. Can be called multiple times with different data
 * segments before finalizing with sha256_final().
 * 
 * @param ctx Pointer to initialized SHA256_CTX structure
 * @param data Pointer to message bytes to add to hash
 * @param len Number of bytes to read from data buffer
 * 
 * @note Can be called multiple times to hash message in chunks
 * @note Automatically invokes sha256_transform() when 64-byte buffer fills
 * @note Maintains running count of total bits processed in ctx->bitlen
 * @warning ctx must be initialized via sha256_init() before first call
 * @warning data must point to at least len bytes of valid readable memory
 * 
 * @see sha256_init() for context initialization
 * @see sha256_final() for completing hash and extracting digest
 * @see sha256_transform() for block processing function
 * 
 * EXAMPLE USAGE:
 * @code
 * SHA256_CTX ctx;
 * sha256_init(&ctx);
 * sha256_update(&ctx, (BYTE*)"Hello ", 6);
 * sha256_update(&ctx, (BYTE*)"World", 5); // Hash "Hello World"
 * BYTE digest[32];
 * sha256_final(&ctx, digest);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - FIPS PUB 180-4 Section 6.2: SHA-256 Hash Computation
 * - Implements message block processing per Section 6.2.2
 * - Handles arbitrary message lengths per Section 5.1 padding requirements
 * 
 * SIDE EFFECTS:
 * - Appends bytes to ctx->data buffer
 * - Increments ctx->datalen for each byte added
 * - Calls sha256_transform() when buffer reaches 64 bytes
 * - Increments ctx->bitlen by 512 for each processed block
 * - Resets ctx->datalen to 0 after processing full block
 * 
 * THREAD SAFETY:
 * Not thread-safe if same ctx accessed concurrently. Re-entrant if different
 * ctx pointers used. Caller must provide synchronization for shared context.
 */
static void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
  WORD i;
  
  for (i = 0; i < len; ++i)
    {
      ctx->data[ctx->datalen] = data[i];
      ctx->datalen++;
      if (ctx->datalen == 64) {
	sha256_transform(ctx, ctx->data);
	ctx->bitlen += 512;
	ctx->datalen = 0;
      }
    }
}

/**
 * @brief Finalize SHA-256 hash and extract digest
 * 
 * @detailed
 * Completes SHA-256 hash computation by applying padding and processing final
 * block(s), then extracting the 32-byte digest from the context state. Implements
 * SHA-256 padding scheme per FIPS PUB 180-4 Section 5.1.1: appends single 1 bit
 * (0x80 byte), pads with zeros to 448 bits mod 512, then appends 64-bit message
 * length. Processes final padded block(s) via sha256_transform(), then extracts
 * digest by converting eight 32-bit state words to 32 bytes using big-endian
 * byte ordering.
 * 
 * @param ctx Pointer to SHA256_CTX with accumulated message data
 * @param hash Pointer to 32-byte buffer to receive SHA-256 digest
 * 
 * @note After calling, ctx is in final state and should not be reused without re-init
 * @note hash buffer must be at least 32 bytes (SHA256_BLOCK_SIZE)
 * @warning ctx must have been initialized and optionally updated before calling
 * @warning hash must point to writable 32-byte buffer
 * 
 * @see sha256_init() for context initialization
 * @see sha256_update() for adding message data
 * @see sha256_transform() for block processing
 * @see FIPS PUB 180-4 Section 5.1.1 for padding specification
 * 
 * EXAMPLE USAGE:
 * @code
 * SHA256_CTX ctx;
 * BYTE digest[SHA256_BLOCK_SIZE];
 * sha256_init(&ctx);
 * sha256_update(&ctx, (BYTE*)"message", 7);
 * sha256_final(&ctx, digest);
 * // digest now contains 32-byte SHA-256 hash
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - FIPS PUB 180-4 Section 5.1.1: SHA-256 padding specification
 * - Appends '1' bit (0x80) followed by zeros per Section 5.1.1
 * - Appends 64-bit message length in bits per Section 5.1.1
 * - Handles messages requiring one or two padding blocks (length < 56 or >= 56 bytes)
 * - Section 6.2: Converts final state to digest using big-endian byte order
 * 
 * SIDE EFFECTS:
 * - Modifies ctx->data buffer with padding (0x80, zeros, message length)
 * - May call sha256_transform() once or twice depending on padding requirements
 * - Increments ctx->bitlen to include final partial block
 * - Writes 32 bytes to hash buffer (final SHA-256 digest)
 * - Leaves ctx in final state (not reusable without re-initialization)
 * 
 * THREAD SAFETY:
 * Not thread-safe if same ctx accessed concurrently. Re-entrant if different
 * ctx and hash pointers used. Caller must provide synchronization for shared resources.
 */
static void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
  WORD i;
  
  i = ctx->datalen;

  /* Pad whatever data is left in the buffer. */
  if (ctx->datalen < 56)
    {
      ctx->data[i++] = 0x80;
      while (i < 56)
	ctx->data[i++] = 0x00;
    }
  else
    {
      ctx->data[i++] = 0x80;
      while (i < 64)
	ctx->data[i++] = 0x00;
      sha256_transform(ctx, ctx->data);
      memset(ctx->data, 0, 56);
    }
  
  /* Append to the padding the total message's length in bits and transform. */
  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  sha256_transform(ctx, ctx->data);
  
  /* Since this implementation uses little endian byte ordering and SHA uses big endian,
     reverse all the bytes when copying the final state to the output hash. */
  for (i = 0; i < 4; ++i)
    {
      hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

#endif
