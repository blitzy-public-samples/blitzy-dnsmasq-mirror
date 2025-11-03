/* dnsmasq is Copyright (c) 2000-2022 Simon Kelley

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
 * @file crypto.c
 * @brief Cryptographic primitive wrappers for DNSSEC signature verification
 *
 * DETAILED PURPOSE
 * ================
 * This module provides a unified interface to the Nettle cryptographic library for DNSSEC
 * validation in dnsmasq. It abstracts cryptographic operations required for verifying DNSSEC
 * signatures, supporting multiple algorithm families including RSA, ECDSA, EdDSA, and optionally
 * GOST. The implementation handles version compatibility across different releases of libnettle
 * (2.0 through 3.6+) and provides algorithm selection and verification dispatch mechanisms.
 *
 * The module serves as the cryptographic backend for dnssec.c, offering signature verification
 * for DNSKEY and RRSIG records according to multiple RFCs. It manages static key structures
 * for performance, implements a "null hash" for EdDSA whole-message signing, and provides
 * hash function lookup facilities.
 *
 * KEY RESPONSIBILITIES
 * ====================
 * - verify(): Main entry point for DNSSEC signature verification across all supported algorithms
 * - verify_func(): Algorithm dispatcher selecting appropriate verification function by algorithm number
 * - dnsmasq_rsa_verify(): RSA signature verification (algorithms 5, 7, 8, 10)
 * - dnsmasq_ecdsa_verify(): ECDSA signature verification (algorithms 13, 14)
 * - dnsmasq_eddsa_verify(): EdDSA signature verification (algorithms 15, 16)
 * - hash_init(): Initialize hash contexts with dynamic memory management
 * - hash_find(): Locate hash function implementations in nettle library
 * - algo_digest_name(): Map DNSSEC algorithm numbers to hash algorithm names
 * - ds_digest_name(): Map DS record digest types to hash algorithm names
 * - nsec3_digest_name(): Map NSEC3 digest types to hash algorithm names
 *
 * DEPENDENCIES
 * ============
 * Included headers:
 * - dnsmasq.h: Core dnsmasq type definitions including struct blockdata
 * - nettle/bignum.h: GMP arbitrary precision integers for RSA operations
 * - nettle/rsa.h: RSA signature verification functions
 * - nettle/ecdsa.h: ECDSA signature verification functions
 * - nettle/ecc-curve.h: Elliptic curve parameters for ECDSA
 * - nettle/eddsa.h: EdDSA signature functions (nettle 3.1+)
 * - nettle/gostdsa.h: GOST signature functions (nettle 3.6+, optional)
 *
 * Called by:
 * - dnssec.c: validate_rrset() for RRSIG signature verification
 * - dnssec.c: validate_keys() for DNSKEY self-signature verification
 *
 * Calls:
 * - blockdata.c: blockdata_retrieve() to extract key material from chain
 * - util.c: whine_malloc() for allocation with error logging
 * - Nettle library functions for cryptographic operations
 *
 * DATA STRUCTURES
 * ===============
 * - struct null_hash_ctx: Context for null hash (EdDSA, lines 59-62)
 * - struct null_hash_digest: Digest container for null hash (EdDSA, lines 53-57)
 * - struct nettle_hash null_hash: Nettle hash interface for EdDSA (lines 108-116)
 * - Static key structures: rsa_public_key, ecc_point instances for algorithm types
 * - Static signature structures: dsa_signature, mpz_t integers for verification
 *
 * COMPILE-TIME OPTIONS
 * ====================
 * - HAVE_DNSSEC: Must be defined to enable DNSSEC cryptographic support (mandatory for this file)
 * - HAVE_CRYPTOHASH: Alternative mode for hash functions only (without full DNSSEC)
 * - HAVE_GOST: Enables GOST algorithm support if defined (optional, nettle 3.6+)
 * - MIN_VERSION(major, minor): Macro to check nettle version for feature availability
 *
 * Algorithm availability by nettle version:
 * - Nettle 2.0+: RSA (algorithms 5, 7, 8, 10), ECDSA (algorithms 13, 14)
 * - Nettle 3.1+: EdDSA Ed25519 (algorithm 15), null_hash infrastructure
 * - Nettle 3.4+: nettle_lookup_hash() for ABI stability
 * - Nettle 3.6+: GOST (algorithm 12), EdDSA Ed448 (algorithm 16)
 *
 * THREADING AND CONCURRENCY
 * ==========================
 * Single-process event-driven model. Functions use static storage for key and signature
 * structures to avoid repeated allocations. This is safe because dnsmasq processes one
 * DNSSEC validation at a time in its single-threaded event loop. The static buffers
 * (null_hash_buff, key structures) are reused across multiple verify operations.
 *
 * Re-entrancy: NOT re-entrant due to static storage. Must not be called from signal
 * handlers or multiple threads.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DNSSEC.md for DNSSEC validation architecture
 * @see dnssec.c for usage in DNSSEC validation pipeline
 */

#include "dnsmasq.h"

#if defined(HAVE_DNSSEC) || defined(HAVE_CRYPTOHASH)

/* Minimal version of nettle */

/* bignum.h includes version.h and works on
   earlier releases of nettle which don't have version.h */
#include <nettle/bignum.h>
#if !defined(NETTLE_VERSION_MAJOR)
#  define NETTLE_VERSION_MAJOR 2
#  define NETTLE_VERSION_MINOR 0
#endif
#define MIN_VERSION(major, minor) ((NETTLE_VERSION_MAJOR == (major) && NETTLE_VERSION_MINOR >= (minor)) || \
				   (NETTLE_VERSION_MAJOR > (major)))

#endif /* defined(HAVE_DNSSEC) || defined(HAVE_CRYPTOHASH) */

#if defined(HAVE_DNSSEC)
#include <nettle/rsa.h>
#include <nettle/ecdsa.h>
#include <nettle/ecc-curve.h>
#if MIN_VERSION(3, 1)
#include <nettle/eddsa.h>
#endif
#if MIN_VERSION(3, 6)
#  include <nettle/gostdsa.h>
#endif

#if MIN_VERSION(3, 1)
/* Implement a "hash-function" to the nettle API, which simply returns
   the input data, concatenated into a single, statically maintained, buffer.

   Used for the EdDSA sigs, which operate on the whole message, rather 
   than a digest. */

/**
 * @struct null_hash_digest
 * @brief Digest structure for null hash function used with EdDSA signatures
 *
 * This structure serves as a pseudo-digest for EdDSA signature verification (algorithms 15 and 16).
 * Unlike traditional cryptographic hash functions that produce fixed-size digests, EdDSA algorithms
 * (Ed25519, Ed448) operate on the entire message data. The null_hash "digest" simply contains a
 * pointer to the accumulated message buffer and its length.
 *
 * LIFECYCLE: Created by null_hash_digest() when finalizing a null_hash context. Points to the
 * statically allocated null_hash_buff. Valid until next null_hash operation overwrites the buffer.
 *
 * MEMORY LAYOUT: 16 bytes on 64-bit systems (8-byte pointer + 8-byte size_t).
 *
 * USAGE PATTERN: Passed to EdDSA verification functions which extract buff and len to access
 * the complete message data for signature verification.
 */
struct null_hash_digest
{
  uint8_t *buff;  /**< Pointer to complete message data in static buffer */
  size_t len;     /**< Length of message data in bytes */
};

/**
 * @struct null_hash_ctx
 * @brief Context structure for null hash function accumulating message data
 *
 * This structure maintains state during null_hash "hashing" operations for EdDSA signatures.
 * It tracks the current length of accumulated data in the static null_hash_buff. The null hash
 * doesn't actually hash data - it concatenates input into a buffer for EdDSA whole-message signing.
 *
 * LIFECYCLE: Initialized by null_hash_init() (sets len=0), updated by null_hash_update()
 * (increments len), finalized by null_hash_digest() (produces null_hash_digest result).
 *
 * MEMORY LAYOUT: sizeof(size_t), typically 8 bytes on 64-bit systems.
 *
 * USAGE PATTERN: Conforms to nettle_hash interface so EdDSA can use standard hash API despite
 * not performing actual hashing.
 */
struct null_hash_ctx
{
  size_t len;  /**< Current length of accumulated data in bytes */
};

static size_t null_hash_buff_sz = 0;
static uint8_t *null_hash_buff = NULL;
#define BUFF_INCR 128

/**
 * @brief Initialize null hash context for EdDSA message accumulation
 *
 * @detailed
 * Resets the null hash context to initial state by setting accumulated length to zero.
 * This prepares the context for a new EdDSA message accumulation operation. The static
 * message buffer null_hash_buff is reused but not cleared, as its contents beyond ctx->len
 * are ignored. This function conforms to the nettle_hash_init_func signature.
 *
 * @param[in,out] ctx Null hash context to initialize, must point to struct null_hash_ctx
 *
 * @note This is a static function implementing the nettle hash interface for EdDSA
 * @warning Context pointer must be valid struct null_hash_ctx, no NULL check performed
 *
 * @see null_hash_update() for accumulating message data
 * @see null_hash_digest() for finalizing and producing digest
 *
 * EXAMPLE USAGE:
 * @code
 * struct null_hash_ctx ctx;
 * null_hash_init(&ctx);
 * // ctx.len is now 0, ready for update operations
 * @endcode
 *
 * RFC COMPLIANCE: Supports RFC 8080 (EdDSA for DNSSEC) signature verification.
 *
 * SIDE EFFECTS: Modifies context len field only. Does not allocate or free memory.
 *
 * THREAD SAFETY: Not thread-safe due to use of static null_hash_buff. Single-threaded use only.
 */
static void null_hash_init(void *ctx)
{
  ((struct null_hash_ctx *)ctx)->len = 0;
}

/**
 * @brief Accumulate message data into null hash buffer for EdDSA verification
 *
 * @detailed
 * Appends input data to the static null_hash_buff, expanding the buffer if necessary.
 * This function concatenates message fragments for EdDSA whole-message signing. Buffer
 * expansion occurs in BUFF_INCR (128 byte) increments to reduce reallocation overhead.
 * Existing data is preserved during buffer expansion. Conforms to nettle_hash_update_func
 * signature.
 *
 * @param[in,out] ctxv Context pointer, must point to struct null_hash_ctx
 * @param[in] length Number of bytes to append from src
 * @param[in] src Source data to append, must be readable for length bytes
 *
 * @note Buffer expansion allocates new_len + BUFF_INCR (128) to reduce future reallocations
 * @warning Silent failure if memory allocation fails - no error indication, data not appended
 * @warning Context and src pointers must be valid, no NULL checks performed
 *
 * @see null_hash_init() for context initialization
 * @see null_hash_digest() for finalizing accumulated data
 * @see whine_malloc() for allocation with logging
 *
 * EXAMPLE USAGE:
 * @code
 * struct null_hash_ctx ctx;
 * null_hash_init(&ctx);
 * unsigned char data[] = "DNS message data";
 * null_hash_update(&ctx, sizeof(data), data);
 * // data now appended to null_hash_buff, ctx.len updated
 * @endcode
 *
 * RFC COMPLIANCE: Supports RFC 8080 (EdDSA for DNSSEC) by accumulating complete message.
 *
 * SIDE EFFECTS: May allocate and free memory for null_hash_buff. Modifies static buffer
 * and context length. Previous buffer freed on expansion.
 *
 * THREAD SAFETY: Not thread-safe due to static buffer modification. Single-threaded use only.
 */
static void null_hash_update(void *ctxv, size_t length, const uint8_t *src)
{
  struct null_hash_ctx *ctx = ctxv;
  size_t new_len = ctx->len + length;
  
  if (new_len > null_hash_buff_sz)
    {
      uint8_t *new;
      
      if (!(new = whine_malloc(new_len + BUFF_INCR)))
	return;

      if (null_hash_buff)
	{
	  if (ctx->len != 0)
	    memcpy(new, null_hash_buff, ctx->len);
	  free(null_hash_buff);
	}
      
      null_hash_buff_sz = new_len + BUFF_INCR;
      null_hash_buff = new;
    }

  memcpy(null_hash_buff + ctx->len, src, length);
  ctx->len += length;
}
 
/**
 * @brief Finalize null hash and produce digest containing message buffer pointer
 *
 * @detailed
 * Produces a "digest" for EdDSA verification by creating a struct null_hash_digest containing
 * a pointer to the accumulated message buffer and its length. Unlike traditional hash digests,
 * this doesn't compute a fixed-size hash - it just packages the complete message data for
 * EdDSA signature verification. Conforms to nettle_hash_digest_func signature. The length
 * parameter is ignored as the digest size is always sizeof(struct null_hash_digest).
 *
 * @param[in] ctx Context pointer, must point to struct null_hash_ctx
 * @param[in] length Digest size (ignored, provided for nettle API compliance)
 * @param[out] dst Output buffer, must be at least sizeof(struct null_hash_digest) bytes,
 *                 interpreted as struct null_hash_digest pointer
 *
 * @note The returned "digest" contains pointers to static buffer, not a copy of data
 * @warning Digest remains valid only until next null_hash operation that may reallocate buffer
 * @warning No NULL checks on ctx or dst parameters
 *
 * @see null_hash_init() for context initialization
 * @see null_hash_update() for accumulating data
 * @see dnsmasq_eddsa_verify() for consuming this digest structure
 *
 * EXAMPLE USAGE:
 * @code
 * struct null_hash_ctx ctx;
 * struct null_hash_digest digest;
 * null_hash_init(&ctx);
 * null_hash_update(&ctx, msg_len, msg_data);
 * null_hash_digest(&ctx, sizeof(digest), (uint8_t*)&digest);
 * // digest.buff points to accumulated message, digest.len contains message length
 * @endcode
 *
 * RFC COMPLIANCE: Supports RFC 8080 (EdDSA for DNSSEC) by providing complete message to verifier.
 *
 * SIDE EFFECTS: Writes to dst buffer. Does not modify context or static buffer.
 *
 * THREAD SAFETY: Not thread-safe due to reference to static buffer. Single-threaded use only.
 */
static void null_hash_digest(void *ctx, size_t length, uint8_t *dst)
{
  (void)length;
  
  ((struct null_hash_digest *)dst)->buff = null_hash_buff;
  ((struct null_hash_digest *)dst)->len = ((struct null_hash_ctx *)ctx)->len;
}

static struct nettle_hash null_hash = {
  "null_hash",
  sizeof(struct null_hash_ctx),
  sizeof(struct null_hash_digest),
  0,
  (nettle_hash_init_func *) null_hash_init,
  (nettle_hash_update_func *) null_hash_update,
  (nettle_hash_digest_func *) null_hash_digest
};

#endif /* MIN_VERSION(3, 1) */

/**
 * @brief Initialize hash context with dynamic buffer management for DNSSEC operations
 *
 * @detailed
 * Allocates or reuses static buffers for hash context and digest storage, expanding buffers
 * as needed for the requested hash algorithm. This function manages persistent storage to
 * avoid repeated allocations across multiple DNSSEC verifications. Buffers are sized to the
 * maximum required by any hash algorithm seen, remaining allocated for program lifetime.
 * After ensuring adequate buffer sizes, initializes the hash context using the hash->init
 * function pointer.
 *
 * @param[in] hash Nettle hash algorithm descriptor, must not be NULL
 * @param[out] ctxp Receives pointer to hash context buffer, must not be NULL
 * @param[out] digestp Receives pointer to digest buffer, must not be NULL
 *
 * @return 1 on success, 0 on memory allocation failure
 * @retval 1 Success, ctxp and digestp set to valid buffers, context initialized
 * @retval 0 Memory allocation failure, ctxp and digestp not modified
 *
 * @note Uses static storage for ctx and digest buffers, expanded on demand
 * @warning Not thread-safe due to static buffer management
 * @warning Buffers never freed - acceptable for long-running daemon
 *
 * @see hash_find() for obtaining hash algorithm descriptor
 * @see whine_malloc() for allocation with error logging
 * @see dnssec.c validate_rrset() for usage in signature verification
 *
 * EXAMPLE USAGE:
 * @code
 * const struct nettle_hash *sha256 = hash_find("sha256");
 * void *ctx;
 * unsigned char *digest;
 * if (hash_init(sha256, &ctx, &digest)) {
 *   sha256->update(ctx, data_len, data);
 *   sha256->digest(ctx, sha256->digest_size, digest);
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Supports RFC 4034 (DNSSEC Resource Records) hash digest computation.
 *
 * SIDE EFFECTS: May allocate or reallocate static buffers. Initializes hash context.
 * Previous buffers freed on expansion.
 *
 * THREAD SAFETY: Not thread-safe due to static storage. Single-threaded event loop only.
 */
int hash_init(const struct nettle_hash *hash, void **ctxp, unsigned char **digestp)
{
  static void *ctx = NULL;
  static unsigned char *digest = NULL;
  static unsigned int ctx_sz = 0;
  static unsigned int digest_sz = 0;

  void *new;

  if (ctx_sz < hash->context_size)
    {
      if (!(new = whine_malloc(hash->context_size)))
	return 0;
      if (ctx)
	free(ctx);
      ctx = new;
      ctx_sz = hash->context_size;
    }
  
  if (digest_sz < hash->digest_size)
    {
      if (!(new = whine_malloc(hash->digest_size)))
	return 0;
      if (digest)
	free(digest);
      digest = new;
      digest_sz = hash->digest_size;
    }

  *ctxp = ctx;
  *digestp = digest;

  hash->init(ctx);

  return 1;
}

/**
 * @brief Verify RSA signature for DNSSEC using nettle library
 *
 * @detailed
 * Verifies RSA signatures for DNSSEC algorithms 5 (RSASHA1), 7 (RSASHA1-NSEC3-SHA1),
 * 8 (RSASHA256), and 10 (RSASHA512). Extracts RSA public key (exponent e and modulus n)
 * from DNSKEY record format, imports signature and key into GMP multi-precision integers,
 * then dispatches to appropriate nettle RSA verification function based on algorithm number.
 * Uses static key structure for performance across multiple verifications.
 *
 * Key format per RFC 3110: 1-byte exponent length (or 0x00 + 2-byte length), exponent bytes,
 * modulus bytes.
 *
 * @param[in] key_data Blockdata chain containing DNSKEY public key in RFC 3110 format
 * @param[in] key_len Length of key data in bytes, must be at least 3
 * @param[in] sig Signature bytes to verify, must not be NULL
 * @param[in] sig_len Length of signature in bytes
 * @param[in] digest Hash digest of signed data, must not be NULL
 * @param[in] digest_len Length of digest (unused, provided for interface compatibility)
 * @param[in] algo DNSSEC algorithm number: 5, 7 (SHA1), 8 (SHA256), or 10 (SHA512)
 *
 * @return 1 if signature valid, 0 if invalid or error
 * @retval 1 Signature mathematically valid for given key and digest
 * @retval 0 Signature invalid, key malformed, or unsupported algorithm
 *
 * @note Uses static rsa_public_key and sig_mpz for performance, reused across calls
 * @warning Not thread-safe due to static storage
 * @warning Algorithm 5/7 (RSA/SHA1) deprecated per RFC 6944 but still supported
 *
 * @see verify() for main entry point dispatching to this function
 * @see blockdata_retrieve() for extracting key material from chain
 * @see dnssec.c validate_rrset() for usage context
 *
 * EXAMPLE USAGE:
 * @code
 * struct blockdata *key = ...; // DNSKEY rdata
 * unsigned char sig[256], digest[32];
 * int valid = dnsmasq_rsa_verify(key, key_len, sig, 256, digest, 32, 8);
 * // valid == 1 if RSA/SHA256 signature correct
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3110: RSA public key encoding in DNS
 * - RFC 4034: DNSSEC Resource Records (RRSIG, DNSKEY)
 * - RFC 5702: SHA-2 algorithms for DNSSEC (algorithms 8, 10)
 *
 * SIDE EFFECTS: Modifies static key and sig_mpz. Allocates static structures on first call.
 *
 * THREAD SAFETY: Not thread-safe due to static storage. Single-threaded use only.
 */
static int dnsmasq_rsa_verify(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
			      unsigned char *digest, size_t digest_len, int algo)
{
  unsigned char *p;
  size_t exp_len;
  
  static struct rsa_public_key *key = NULL;
  static mpz_t sig_mpz;

  (void)digest_len;
  
  if (key == NULL)
    {
      if (!(key = whine_malloc(sizeof(struct rsa_public_key))))
	return 0;
      
      nettle_rsa_public_key_init(key);
      mpz_init(sig_mpz);
    }
  
  if ((key_len < 3) || !(p = blockdata_retrieve(key_data, key_len, NULL)))
    return 0;
  
  key_len--;
  if ((exp_len = *p++) == 0)
    {
      GETSHORT(exp_len, p);
      key_len -= 2;
    }
  
  if (exp_len >= key_len)
    return 0;
  
  key->size =  key_len - exp_len;
  mpz_import(key->e, exp_len, 1, 1, 0, 0, p);
  mpz_import(key->n, key->size, 1, 1, 0, 0, p + exp_len);

  mpz_import(sig_mpz, sig_len, 1, 1, 0, 0, sig);
  
  switch (algo)
    {
    case 5: case 7:
      return nettle_rsa_sha1_verify_digest(key, digest, sig_mpz);
    case 8:
      return nettle_rsa_sha256_verify_digest(key, digest, sig_mpz);
    case 10:
      return nettle_rsa_sha512_verify_digest(key, digest, sig_mpz);
    }

  return 0;
}  

/**
 * @brief Verify ECDSA signature for DNSSEC using elliptic curve cryptography
 *
 * @detailed
 * Verifies ECDSA signatures for DNSSEC algorithms 13 (ECDSAP256SHA256) and 14 (ECDSAP384SHA384).
 * Algorithm 13 uses NIST P-256 curve (secp256r1) with 32-byte coordinates; algorithm 14 uses
 * NIST P-384 curve (secp384r1) with 48-byte coordinates. Extracts public key point (x, y) from
 * DNSKEY format, signature components (r, s) from RRSIG format, validates key point is on curve,
 * then verifies signature using nettle ECDSA functions. Static key structures maintained per
 * curve for performance.
 *
 * Key format per RFC 6605: x coordinate (t bytes), y coordinate (t bytes) where t=32 for P-256,
 * t=48 for P-384.
 * Signature format: r component (t bytes), s component (t bytes).
 *
 * @param[in] key_data Blockdata chain containing ECDSA public key in RFC 6605 format
 * @param[in] key_len Length of key data, must equal 2*t (64 for algo 13, 96 for algo 14)
 * @param[in] sig Signature bytes in (r, s) format, must not be NULL
 * @param[in] sig_len Length of signature, must equal 2*t
 * @param[in] digest Hash digest of signed data, must not be NULL
 * @param[in] digest_len Length of digest in bytes
 * @param[in] algo DNSSEC algorithm number: 13 (P-256/SHA256) or 14 (P-384/SHA384)
 *
 * @return 1 if signature valid, 0 if invalid or error
 * @retval 1 Signature mathematically valid, key point on curve
 * @retval 0 Signature invalid, key malformed, point not on curve, or length mismatch
 *
 * @note Maintains separate static ecc_point structures for P-256 and P-384 curves
 * @note Strict length checking: sig_len and key_len must exactly equal 2*t
 * @warning Not thread-safe due to static key structures
 * @warning ecc_point_set() validates point is on curve, returns 0 if invalid
 *
 * @see verify() for main entry point dispatching to this function
 * @see blockdata_retrieve() for extracting key material
 * @see dnssec.c validate_rrset() for usage context
 *
 * EXAMPLE USAGE:
 * @code
 * struct blockdata *key = ...; // DNSKEY with P-256 public key
 * unsigned char sig[64], digest[32];
 * int valid = dnsmasq_ecdsa_verify(key, 64, sig, 64, digest, 32, 13);
 * // valid == 1 if ECDSA P-256 signature correct
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 6605: ECDSA for DNSSEC (algorithms 13 and 14)
 * - RFC 4034: DNSSEC Resource Records
 *
 * SIDE EFFECTS: Modifies static key points and signature structure. Allocates static
 * structures on first use for each curve.
 *
 * THREAD SAFETY: Not thread-safe due to static storage. Single-threaded use only.
 */
static int dnsmasq_ecdsa_verify(struct blockdata *key_data, unsigned int key_len, 
				unsigned char *sig, size_t sig_len,
				unsigned char *digest, size_t digest_len, int algo)
{
  unsigned char *p;
  unsigned int t;
  struct ecc_point *key;

  static struct ecc_point *key_256 = NULL, *key_384 = NULL;
  static mpz_t x, y;
  static struct dsa_signature *sig_struct;
#if !MIN_VERSION(3, 4)
#define nettle_get_secp_256r1() (&nettle_secp_256r1)
#define nettle_get_secp_384r1() (&nettle_secp_384r1)
#endif
  
  if (!sig_struct)
    {
      if (!(sig_struct = whine_malloc(sizeof(struct dsa_signature))))
	return 0;
      
      nettle_dsa_signature_init(sig_struct);
      mpz_init(x);
      mpz_init(y);
    }
  
  switch (algo)
    {
    case 13:
      if (!key_256)
	{
	  if (!(key_256 = whine_malloc(sizeof(struct ecc_point))))
	    return 0;
	  
	  nettle_ecc_point_init(key_256, nettle_get_secp_256r1());
	}
      
      key = key_256;
      t = 32;
      break;
      
    case 14:
      if (!key_384)
	{
	  if (!(key_384 = whine_malloc(sizeof(struct ecc_point))))
	    return 0;
	  
	  nettle_ecc_point_init(key_384, nettle_get_secp_384r1());
	}
      
      key = key_384;
      t = 48;
      break;
        
    default:
      return 0;
    }
  
  if (sig_len != 2*t || key_len != 2*t ||
      !(p = blockdata_retrieve(key_data, key_len, NULL)))
    return 0;
  
  mpz_import(x, t , 1, 1, 0, 0, p);
  mpz_import(y, t , 1, 1, 0, 0, p + t);

  if (!ecc_point_set(key, x, y))
    return 0;
  
  mpz_import(sig_struct->r, t, 1, 1, 0, 0, sig);
  mpz_import(sig_struct->s, t, 1, 1, 0, 0, sig + t);
  
  return nettle_ecdsa_verify(key, digest_len, digest, sig_struct);
}

#if MIN_VERSION(3, 6)
/**
 * @brief Verify GOST R 34.10-2001 signature for DNSSEC (algorithm 12)
 *
 * @detailed
 * Verifies GOST digital signatures for DNSSEC algorithm 12 (ECC-GOST). GOST is a Russian
 * cryptographic standard using elliptic curve GOST R 34.10-2001 on curve id-GostR3410-2001-
 * CryptoPro-A-ParamSet (also known as GOST 256-bit curve). Uses 32-byte coordinates for
 * public key point and 32-byte r, s signature components. This algorithm is primarily used
 * in Russian Federation networks. Requires nettle 3.6 or later for GOST support.
 *
 * Key format: x coordinate (32 bytes), y coordinate (32 bytes).
 * Signature format: r component (32 bytes), s component (32 bytes).
 *
 * @param[in] key_data Blockdata chain containing GOST public key
 * @param[in] key_len Length of key data, must equal 64 bytes
 * @param[in] sig Signature bytes in (r, s) format, must not be NULL
 * @param[in] sig_len Length of signature, must equal 64 bytes
 * @param[in] digest Hash digest of signed data (GOST R 34.11-94 hash), must not be NULL
 * @param[in] digest_len Length of digest in bytes
 * @param[in] algo DNSSEC algorithm number, must be 12 (ECC-GOST)
 *
 * @return 1 if signature valid, 0 if invalid or error
 * @retval 1 Signature mathematically valid for GOST algorithm
 * @retval 0 Signature invalid, key malformed, point not on curve, length mismatch, or algo != 12
 *
 * @note Only available when compiled with nettle 3.6 or later
 * @note Strict validation: algo must be 12, key_len and sig_len must be exactly 64
 * @warning Not thread-safe due to static gost_key structure
 * @warning Limited deployment - primarily for Russian Federation DNSSEC
 *
 * @see verify() for main entry point dispatching to this function
 * @see blockdata_retrieve() for extracting key material
 * @see algo_digest_name() which maps algorithm 12 to "gosthash94"
 *
 * EXAMPLE USAGE:
 * @code
 * #if MIN_VERSION(3, 6)
 * struct blockdata *key = ...; // DNSKEY with GOST public key
 * unsigned char sig[64], digest[32];
 * int valid = dnsmasq_gostdsa_verify(key, 64, sig, 64, digest, 32, 12);
 * // valid == 1 if GOST signature correct
 * #endif
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 5933: GOST R 34.10-2001 for DNSSEC (algorithm 12)
 * - RFC 4034: DNSSEC Resource Records
 *
 * SIDE EFFECTS: Modifies static gost_key and signature structure. Allocates static
 * structures on first use.
 *
 * THREAD SAFETY: Not thread-safe due to static storage. Single-threaded use only.
 */
static int dnsmasq_gostdsa_verify(struct blockdata *key_data, unsigned int key_len, 
				  unsigned char *sig, size_t sig_len,
				  unsigned char *digest, size_t digest_len, int algo)
{
  unsigned char *p;
  
  static struct ecc_point *gost_key = NULL;
  static mpz_t x, y;
  static struct dsa_signature *sig_struct;

  if (algo != 12 ||
      sig_len != 64 || key_len != 64 ||
      !(p = blockdata_retrieve(key_data, key_len, NULL)))
    return 0;
  
  if (!sig_struct)
    {
      if (!(sig_struct = whine_malloc(sizeof(struct dsa_signature))) ||
	  !(gost_key = whine_malloc(sizeof(struct ecc_point))))
	return 0;
      
      nettle_dsa_signature_init(sig_struct);
      nettle_ecc_point_init(gost_key, nettle_get_gost_gc256b());
      mpz_init(x);
      mpz_init(y);
    }
    
  mpz_import(x, 32 , 1, 1, 0, 0, p);
  mpz_import(y, 32 , 1, 1, 0, 0, p + 32);

  if (!ecc_point_set(gost_key, x, y))
    return 0;
  
  mpz_import(sig_struct->r, 32, 1, 1, 0, 0, sig);
  mpz_import(sig_struct->s, 32, 1, 1, 0, 0, sig + 32);
  
  return nettle_gostdsa_verify(gost_key, digest_len, digest, sig_struct);
}
#endif

#if MIN_VERSION(3, 1)
/**
 * @brief Verify EdDSA signature for DNSSEC using Ed25519 or Ed448 algorithms
 *
 * @detailed
 * Verifies Edwards-curve Digital Signature Algorithm (EdDSA) signatures for DNSSEC algorithm 15
 * (Ed25519) and algorithm 16 (Ed448, nettle 3.6+). Unlike RSA and ECDSA which hash messages
 * before signing, EdDSA operates on the complete message. The digest parameter is actually a
 * struct null_hash_digest containing a pointer to the full message buffer accumulated by the
 * null_hash functions. Ed25519 uses Curve25519 with 32-byte keys and 64-byte signatures;
 * Ed448 uses Curve448 with 57-byte keys and 114-byte signatures.
 *
 * @param[in] key_data Blockdata chain containing EdDSA public key
 * @param[in] key_len Length of key: 32 bytes (Ed25519) or 57 bytes (Ed448)
 * @param[in] sig Signature bytes, must not be NULL
 * @param[in] sig_len Length of signature: 64 bytes (Ed25519) or 114 bytes (Ed448)
 * @param[in] digest Actually struct null_hash_digest pointer containing message data
 * @param[in] digest_len Must equal sizeof(struct null_hash_digest)
 * @param[in] algo DNSSEC algorithm: 15 (Ed25519) or 16 (Ed448)
 *
 * @return 1 if signature valid, 0 if invalid or error
 * @retval 1 EdDSA signature mathematically valid for message and public key
 * @retval 0 Signature invalid, key/signature length mismatch, or unsupported algorithm
 *
 * @note Ed25519 requires nettle 3.1+, Ed448 requires nettle 3.6+
 * @note digest is not a hash digest but complete message via null_hash mechanism
 * @note Strict length validation: ED25519_KEY_SIZE=32, ED25519_SIGNATURE_SIZE=64,
 *       ED448_KEY_SIZE=57, ED448_SIGNATURE_SIZE=114
 * @warning digest_len != sizeof(struct null_hash_digest) causes immediate failure
 *
 * @see null_hash_init(), null_hash_update(), null_hash_digest() for message accumulation
 * @see verify() for main entry point dispatching to this function
 * @see blockdata_retrieve() for extracting key material
 *
 * EXAMPLE USAGE:
 * @code
 * struct blockdata *key = ...; // Ed25519 public key (32 bytes)
 * unsigned char sig[64];
 * struct null_hash_digest msg_digest = ...; // from null_hash
 * int valid = dnsmasq_eddsa_verify(key, 32, sig, 64,
 *                                   (unsigned char*)&msg_digest,
 *                                   sizeof(msg_digest), 15);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 8080: EdDSA for DNSSEC (algorithms 15 and 16)
 * - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
 * - RFC 4034: DNSSEC Resource Records
 *
 * SIDE EFFECTS: None - no static storage in this function.
 *
 * THREAD SAFETY: Thread-safe for this function itself, but depends on null_hash_buff which
 * is not thread-safe. Overall system is single-threaded.
 */
static int dnsmasq_eddsa_verify(struct blockdata *key_data, unsigned int key_len, 
				unsigned char *sig, size_t sig_len,
				unsigned char *digest, size_t digest_len, int algo)
{
  unsigned char *p;
   
  if (digest_len != sizeof(struct null_hash_digest) ||
      !(p = blockdata_retrieve(key_data, key_len, NULL)))
    return 0;
  
  /* The "digest" returned by the null_hash function is simply a struct null_hash_digest
     which has a pointer to the actual data and a length, because the buffer
     may need to be extended during "hashing". */
  
  switch (algo)
    {
    case 15:
      if (key_len != ED25519_KEY_SIZE ||
	  sig_len != ED25519_SIGNATURE_SIZE)
	return 0;

      return ed25519_sha512_verify(p,
				   ((struct null_hash_digest *)digest)->len,
				   ((struct null_hash_digest *)digest)->buff,
				   sig);
      
#if MIN_VERSION(3, 6)
    case 16:
      if (key_len != ED448_KEY_SIZE ||
	  sig_len != ED448_SIGNATURE_SIZE)
	return 0;

      return ed448_shake256_verify(p,
				   ((struct null_hash_digest *)digest)->len,
				   ((struct null_hash_digest *)digest)->buff,
				   sig);
#endif

    }

  return 0;
}
#endif

/**
 * @brief Select appropriate signature verification function for DNSSEC algorithm
 *
 * @detailed
 * Dispatches to the correct signature verification function based on DNSSEC algorithm number.
 * Performs runtime validation that the required hash function is available in nettle before
 * returning the verification function pointer. This indirection allows verify() to be
 * algorithm-agnostic. Returns NULL for unsupported algorithms or if the associated hash
 * function is not available in the linked nettle library version.
 *
 * Supported algorithms:
 * - 5, 7: RSA/SHA1 (deprecated but supported)
 * - 8: RSA/SHA256
 * - 10: RSA/SHA512
 * - 12: GOST R 34.10-2001 (nettle 3.6+ only)
 * - 13: ECDSA P-256/SHA256
 * - 14: ECDSA P-384/SHA384
 * - 15: Ed25519 (nettle 3.1+ only)
 * - 16: Ed448 (nettle 3.6+ only)
 *
 * @param[in] algo DNSSEC algorithm number from RRSIG or DNSKEY record
 *
 * @return Function pointer to algorithm-specific verify function, or NULL if unsupported
 * @retval dnsmasq_rsa_verify For RSA algorithms (5, 7, 8, 10)
 * @retval dnsmasq_ecdsa_verify For ECDSA algorithms (13, 14)
 * @retval dnsmasq_gostdsa_verify For GOST algorithm (12, if nettle 3.6+)
 * @retval dnsmasq_eddsa_verify For EdDSA algorithms (15, 16, if nettle 3.1+)
 * @retval NULL Algorithm unsupported or hash function not available
 *
 * @note Hash function availability checked via hash_find(algo_digest_name(algo))
 * @note Algorithm availability depends on nettle version at compile time
 * @warning Algorithms 1 (RSA/MD5), 3 (DSA), 6 (DSA-NSEC3) are NOT supported (deprecated)
 *
 * @see verify() for main entry point using this dispatcher
 * @see algo_digest_name() for algorithm-to-hash mapping
 * @see hash_find() for hash function availability check
 *
 * EXAMPLE USAGE:
 * @code
 * int (*verify_fn)(struct blockdata*, unsigned int, unsigned char*, size_t,
 *                  unsigned char*, size_t, int);
 * verify_fn = verify_func(8); // Get RSA/SHA256 verifier
 * if (verify_fn) {
 *   int valid = verify_fn(key, key_len, sig, sig_len, digest, digest_len, 8);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 8624: DNSSEC algorithm implementation requirements (defines MUST/MUST NOT implement)
 * - RFC 6944: Algorithms 1, 3, 6 deprecated (not supported here)
 *
 * SIDE EFFECTS: None.
 *
 * THREAD SAFETY: Thread-safe.
 */
static int (*verify_func(int algo))(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
			     unsigned char *digest, size_t digest_len, int algo)
{
    
  /* Ensure at runtime that we have support for this digest */
  if (!hash_find(algo_digest_name(algo)))
    return NULL;
  
  /* This switch defines which sig algorithms we support, can't introspect Nettle for that. */
  switch (algo)
    {
    case 5: case 7: case 8: case 10:
      return dnsmasq_rsa_verify;

#if MIN_VERSION(3, 6)
    case 12:
      return dnsmasq_gostdsa_verify;
#endif
      
    case 13: case 14:
      return dnsmasq_ecdsa_verify;
      
#if MIN_VERSION(3, 1)
    case 15: case 16:
      return dnsmasq_eddsa_verify;
#endif
    }
  
  return NULL;
}

/**
 * @brief Verify DNSSEC signature using appropriate cryptographic algorithm
 *
 * @detailed
 * Main entry point for DNSSEC signature verification. Dispatches to algorithm-specific
 * verification functions based on the DNSSEC algorithm number. Supports RSA, ECDSA, EdDSA,
 * and optionally GOST signature algorithms. Returns success/failure indication. This function
 * is called by dnssec.c during RRSIG validation to verify that a signature over an RRset
 * was created by the corresponding DNSKEY.
 *
 * Algorithm selection is performed by verify_func(), which validates hash function availability
 * and returns the appropriate verification function pointer. Unsupported algorithms or missing
 * hash functions result in verification failure.
 *
 * @param[in] key_data Blockdata chain containing public key from DNSKEY record, must not be NULL
 * @param[in] key_len Length of public key data in bytes
 * @param[in] sig Signature bytes from RRSIG record, must not be NULL
 * @param[in] sig_len Length of signature in bytes
 * @param[in] digest Hash digest of signed data (or null_hash_digest for EdDSA), must not be NULL
 * @param[in] digest_len Length of digest in bytes
 * @param[in] algo DNSSEC algorithm number from RRSIG/DNSKEY records
 *
 * @return 1 if signature valid, 0 if invalid or unsupported
 * @retval 1 Cryptographic signature verification succeeded
 * @retval 0 Signature verification failed, algorithm unsupported, or hash unavailable
 *
 * @note For EdDSA (algorithms 15, 16), digest is struct null_hash_digest, not actual hash
 * @note Function pointers used for algorithm dispatch to avoid code duplication
 * @warning Zero return can indicate either cryptographic failure or unsupported algorithm
 *
 * @see verify_func() for algorithm dispatcher
 * @see dnssec.c validate_rrset() for caller context
 * @see blockdata_retrieve() for key extraction
 *
 * EXAMPLE USAGE:
 * @code
 * struct blockdata *key = ...; // from DNSKEY
 * unsigned char *sig = ...; // from RRSIG
 * unsigned char digest[32];
 * // Compute SHA256 digest of RRset...
 * int valid = verify(key, key_len, sig, sig_len, digest, 32, 8);
 * if (valid)
 *   printf("RSA/SHA256 signature valid\n");
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4034: DNSSEC Resource Records (RRSIG, DNSKEY)
 * - RFC 4035: Protocol Modifications for DNSSEC (validation process)
 * - RFC 5702: RSA/SHA-2 for DNSSEC (algorithms 8, 10)
 * - RFC 6605: ECDSA for DNSSEC (algorithms 13, 14)
 * - RFC 8080: EdDSA for DNSSEC (algorithms 15, 16)
 * - RFC 5933: GOST for DNSSEC (algorithm 12)
 *
 * SIDE EFFECTS: Calls algorithm-specific verify functions which use static storage.
 *
 * THREAD SAFETY: Not thread-safe due to algorithm-specific functions using static storage.
 * Single-threaded event loop only.
 */
int verify(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
	   unsigned char *digest, size_t digest_len, int algo)
{

  int (*func)(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
	      unsigned char *digest, size_t digest_len, int algo);
  
  func = verify_func(algo);
  
  if (!func)
    return 0;

  return (*func)(key_data, key_len, sig, sig_len, digest, digest_len, algo);
}

/* Note the ds_digest_name(), algo_digest_name() and nsec3_digest_name()
   define which algo numbers we support. If algo_digest_name() returns
   non-NULL for an algorithm number, we assume that algorithm is 
   supported by verify(). */

/**
 * @brief Map DS record digest type to hash algorithm name
 *
 * @detailed
 * Converts DS (Delegation Signer) record digest type number to the corresponding hash
 * algorithm name used by nettle library. DS records contain a hash of a DNSKEY record,
 * and this function identifies which hash algorithm was used. The returned name can be
 * passed to hash_find() to obtain the nettle hash function implementation. Returns NULL
 * for unsupported or unrecognized digest types.
 *
 * Supported digest types per IANA registry:
 * - 1: SHA-1 (deprecated but supported)
 * - 2: SHA-256 (recommended)
 * - 3: GOST R 34.11-94 (Russian standard)
 * - 4: SHA-384
 *
 * @param[in] digest DS record digest type number (from DS record)
 *
 * @return Hash algorithm name string, or NULL if unsupported
 * @retval "sha1" For digest type 1
 * @retval "sha256" For digest type 2 (recommended)
 * @retval "gosthash94" For digest type 3
 * @retval "sha384" For digest type 4
 * @retval NULL For unrecognized digest types
 *
 * @note Digest type 1 (SHA-1) deprecated per RFC 8624 but still supported
 * @note Returned string is static constant, do not free
 *
 * @see hash_find() for obtaining hash function from name
 * @see dnssec.c for DS record validation usage
 *
 * EXAMPLE USAGE:
 * @code
 * int ds_digest_type = 2; // from DS record
 * char *hash_name = ds_digest_name(ds_digest_type);
 * if (hash_name) {
 *   const struct nettle_hash *hash = hash_find(hash_name);
 *   // Use hash to verify DS record...
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4034: DS record format and digest types
 * - RFC 4509: SHA-256 for DS records (digest type 2)
 * - RFC 5933: GOST for DNSSEC (digest type 3)
 * - RFC 6605: SHA-384 for DS records (digest type 4)
 * - RFC 8624: DNSSEC algorithm and digest recommendations
 *
 * IANA REGISTRY: http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
 *
 * SIDE EFFECTS: None.
 *
 * THREAD SAFETY: Thread-safe.
 */
char *ds_digest_name(int digest)
{
  switch (digest)
    {
    case 1: return "sha1";
    case 2: return "sha256";
    case 3: return "gosthash94";
    case 4: return "sha384";
    default: return NULL;
    }
}
 
/**
 * @brief Map DNSSEC signature algorithm to hash digest name
 *
 * @detailed
 * Converts DNSSEC signature algorithm number to the corresponding hash algorithm name used
 * for computing message digests before signature verification. This mapping defines which
 * algorithms dnsmasq supports - returning non-NULL indicates the algorithm is implemented.
 * The returned name can be passed to hash_find() to obtain the nettle hash implementation.
 *
 * Returns NULL for deprecated algorithms per RFC 6944 and RFC 8624 (RSA/MD5, DSA variants).
 * EdDSA algorithms (15, 16) return "null_hash" because they operate on whole messages rather
 * than pre-computed digests.
 *
 * Supported algorithms:
 * - 5, 7: RSA/SHA1 (deprecated but supported for compatibility)
 * - 8: RSA/SHA256 (recommended)
 * - 10: RSA/SHA512
 * - 12: GOST R 34.10-2001 with GOST R 34.11-94 hash
 * - 13: ECDSA P-256 with SHA256
 * - 14: ECDSA P-384 with SHA384
 * - 15: Ed25519 with SHA512 (uses null_hash)
 * - 16: Ed448 with SHAKE256 (uses null_hash)
 *
 * Unsupported (return NULL):
 * - 1: RSA/MD5 (Must Not Implement per RFC 6944)
 * - 2: Diffie-Hellman (not a signature algorithm)
 * - 3, 6: DSA variants (Must Not Implement per RFC 8624)
 *
 * @param[in] algo DNSSEC algorithm number from RRSIG or DNSKEY record
 *
 * @return Hash algorithm name string, or NULL if algorithm unsupported
 * @retval "sha1" For algorithms 5, 7 (deprecated)
 * @retval "sha256" For algorithms 8, 13 (recommended)
 * @retval "sha384" For algorithm 14
 * @retval "sha512" For algorithm 10
 * @retval "gosthash94" For algorithm 12
 * @retval "null_hash" For algorithms 15, 16 (EdDSA whole-message)
 * @retval NULL For unsupported/deprecated algorithms
 *
 * @note Non-NULL return indicates algorithm support in verify()
 * @note Returned string is static constant, do not free
 * @note EdDSA "null_hash" is special - not a real hash, accumulates message data
 *
 * @see verify_func() which uses this to check algorithm support
 * @see hash_find() for obtaining hash function from name
 * @see dnssec.c validate_rrset() for usage in signature verification
 *
 * EXAMPLE USAGE:
 * @code
 * int algo = 8; // RSA/SHA256 from RRSIG
 * char *hash_name = algo_digest_name(algo);
 * if (hash_name) {
 *   const struct nettle_hash *hash = hash_find(hash_name);
 *   // Hash is available, algorithm supported
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4034: DNSSEC algorithm numbers
 * - RFC 5702: RSA/SHA-2 (algorithms 8, 10)
 * - RFC 6605: ECDSA (algorithms 13, 14)
 * - RFC 8080: EdDSA (algorithms 15, 16)
 * - RFC 5933: GOST (algorithm 12)
 * - RFC 6944: Algorithm implementation requirements (deprecates RSA/MD5)
 * - RFC 8624: Updated algorithm recommendations (deprecates DSA)
 *
 * IANA REGISTRY: http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
 *
 * SIDE EFFECTS: None.
 *
 * THREAD SAFETY: Thread-safe.
 */
char *algo_digest_name(int algo)
{
  switch (algo)
    {
    case 1: return NULL;          /* RSA/MD5 - Must Not Implement.  RFC 6944 para 2.3. */
    case 2: return NULL;          /* Diffie-Hellman */
    case 3: return NULL; ;        /* DSA/SHA1 - Must Not Implement. RFC 8624 section 3.1 */ 
    case 5: return "sha1";        /* RSA/SHA1 */
    case 6: return NULL;          /* DSA-NSEC3-SHA1 - Must Not Implement. RFC 8624 section 3.1 */
    case 7: return "sha1";        /* RSASHA1-NSEC3-SHA1 */
    case 8: return "sha256";      /* RSA/SHA-256 */
    case 10: return "sha512";     /* RSA/SHA-512 */
    case 12: return "gosthash94"; /* ECC-GOST */
    case 13: return "sha256";     /* ECDSAP256SHA256 */
    case 14: return "sha384";     /* ECDSAP384SHA384 */ 	
    case 15: return "null_hash";  /* ED25519 */
    case 16: return "null_hash";  /* ED448 */
    default: return NULL;
    }
}
  
/**
 * @brief Map NSEC3 hash algorithm to hash digest name
 *
 * @detailed
 * Converts NSEC3 hash algorithm number to the corresponding hash algorithm name used by
 * nettle library. NSEC3 records use hashed owner names for authenticated denial of existence
 * with opt-out support. Currently only SHA-1 is defined and supported for NSEC3. The returned
 * name can be passed to hash_find() to obtain the nettle hash function for NSEC3 hash
 * computation and verification.
 *
 * NSEC3 hashing differs from signature hashing - it's used to hash domain names with salt
 * and iteration count for the NSEC3 chain, not for signature verification.
 *
 * @param[in] digest NSEC3 hash algorithm number from NSEC3/NSEC3PARAM record
 *
 * @return Hash algorithm name string, or NULL if unsupported
 * @retval "sha1" For digest type 1 (currently the only defined NSEC3 hash)
 * @retval NULL For unrecognized digest types
 *
 * @note Only SHA-1 (type 1) is currently defined for NSEC3 per RFC 5155
 * @note Unlike signature algorithms, SHA-1 is not deprecated for NSEC3
 * @note Returned string is static constant, do not free
 *
 * @see hash_find() for obtaining hash function from name
 * @see dnssec.c for NSEC3 proof validation usage
 *
 * EXAMPLE USAGE:
 * @code
 * int nsec3_hash_algo = 1; // from NSEC3 record
 * char *hash_name = nsec3_digest_name(nsec3_hash_algo);
 * if (hash_name) {
 *   const struct nettle_hash *hash = hash_find(hash_name);
 *   // Hash domain name with salt and iterations for NSEC3...
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 5155: NSEC3 hashed authenticated denial of existence
 * - RFC 4034: DNSSEC Resource Records (base specification)
 *
 * IANA REGISTRY: http://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml
 *
 * SIDE EFFECTS: None.
 *
 * THREAD SAFETY: Thread-safe.
 */
char *nsec3_digest_name(int digest)
{
  switch (digest)
    {
    case 1: return "sha1";
    default: return NULL;
    }
}

#endif /* defined(HAVE_DNSSEC) */

#if defined(HAVE_DNSSEC) || defined(HAVE_CRYPTOHASH)
/**
 * @brief Locate hash function implementation in nettle library by name
 *
 * @detailed
 * Searches for a hash function in the nettle library by algorithm name (e.g., "sha256",
 * "sha1"). Returns a pointer to the nettle_hash structure containing function pointers
 * for init, update, and digest operations. Handles special case of "null_hash" for EdDSA
 * (which doesn't hash but accumulates complete message). Uses nettle_lookup_hash() on
 * nettle 3.4+ for ABI stability, or iterates nettle_hashes array on older versions.
 *
 * This function provides version-independent access to nettle hash functions, abstracting
 * differences between nettle library versions. Returns NULL if the named hash is not
 * available in the linked nettle version.
 *
 * @param[in] name Hash algorithm name string (e.g., "sha256", "sha1", "sha384", "gosthash94",
 *                 "null_hash"), must be NULL-terminated
 *
 * @return Pointer to nettle_hash descriptor, or NULL if not found
 * @retval &null_hash For "null_hash" on nettle 3.1+ with HAVE_DNSSEC (EdDSA support)
 * @retval nettle_hash* For valid hash names available in linked nettle version
 * @retval NULL If name is NULL or hash not found in nettle library
 *
 * @note Special handling for "null_hash" used by EdDSA algorithms (15, 16)
 * @note Uses nettle_lookup_hash() on nettle 3.4+ for ABI safety
 * @note Falls back to nettle_hashes array iteration on nettle 2.0-3.3
 * @warning Returned pointer is to static data in nettle library, do not free
 *
 * @see hash_init() for using returned hash descriptor
 * @see algo_digest_name() for obtaining hash name from algorithm number
 * @see ds_digest_name() for DS digest names
 * @see nsec3_digest_name() for NSEC3 hash names
 *
 * EXAMPLE USAGE:
 * @code
 * const struct nettle_hash *sha256 = hash_find("sha256");
 * if (sha256) {
 *   void *ctx;
 *   unsigned char *digest;
 *   if (hash_init(sha256, &ctx, &digest)) {
 *     sha256->update(ctx, data_len, data);
 *     sha256->digest(ctx, sha256->digest_size, digest);
 *   }
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Supports hash algorithms required by RFC 4034 (DNSSEC) and related RFCs.
 *
 * SIDE EFFECTS: None.
 *
 * THREAD SAFETY: Thread-safe (accesses read-only nettle data).
 */
const struct nettle_hash *hash_find(char *name)
{
  if (!name)
    return NULL;
  
#if MIN_VERSION(3,1) && defined(HAVE_DNSSEC)
  /* We provide a "null" hash which returns the input data as digest. */
  if (strcmp(null_hash.name, name) == 0)
    return &null_hash;
#endif
  
  /* libnettle >= 3.4 provides nettle_lookup_hash() which avoids nasty ABI
     incompatibilities if sizeof(nettle_hashes) changes between library
     versions. */
#if MIN_VERSION(3, 4)
  return nettle_lookup_hash(name);
#else
  {
    int i;

    for (i = 0; nettle_hashes[i]; i++)
      if (strcmp(nettle_hashes[i]->name, name) == 0)
	return nettle_hashes[i];
  }
  
  return NULL;
#endif
}

#endif /* defined(HAVE_DNSSEC) || defined(HAVE_CRYPTOHASH) */
