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

/* The SURF random number generator was taken from djbdns-1.05, by 
   Daniel J Bernstein, which is public domain. */

/**
 * @file util.c
 * @brief Portable utility functions and SURF random number generator
 *
 * DETAILED PURPOSE:
 * This file provides a comprehensive collection of portable helper functions used throughout
 * dnsmasq for common operations including cryptographically-strong random number generation,
 * safe memory allocation with error handling, network address manipulation and comparison,
 * string operations, time management, and I/O utilities. The centerpiece is the SURF
 * (Secure Universal Random Function) random number generator taken from djbdns-1.05 by
 * Daniel J Bernstein (public domain), which provides cryptographic-quality randomness
 * essential for DNS query ID generation and source port randomization to prevent cache
 * poisoning attacks.
 *
 * KEY RESPONSIBILITIES:
 * - rand_init(), rand16(), rand32(), rand64() - SURF random number generation for DNS security
 * - safe_malloc(), whine_malloc() - Memory allocation with error handling (die vs log)
 * - canonicalise() - Domain name canonicalization with IDN (Internationalized Domain Names) support
 * - legal_hostname() - Hostname validation per DNS specifications
 * - sockaddr_isequal(), sa_len() - Socket address comparison and size calculation
 * - prettyprint_addr(), prettyprint_time() - Human-readable formatting of addresses and time intervals
 * - read_write() - Reliable I/O wrapper handling interrupts and partial reads/writes
 * - expand_buf() - Dynamic buffer expansion for packet handling
 * - hostname_order(), hostname_isequal(), hostname_issubdomain() - Case-insensitive DNS name comparison
 * - is_same_net(), is_same_net6() - Network prefix matching for IPv4/IPv6
 * - retry_send() - Network send retry logic with exponential backoff
 *
 * DEPENDENCIES:
 * - dnsmasq.h - Core type definitions (union mysockaddr, u32, u64, etc.)
 * - libidn2 (optional) - IDN support if HAVE_LIBIDN2 defined
 * - libidna (optional) - Legacy IDN support if HAVE_IDN defined
 * - /dev/urandom or /dev/random - Entropy source for SURF RNG initialization (RANDFILE)
 * Called by: All major dnsmasq modules (forward.c, cache.c, dhcp.c, network.c, option.c)
 * Calls: Standard C library functions, IDN library functions conditionally
 *
 * DATA STRUCTURES:
 * - static u32 seed[32] - SURF RNG seed state (lines 39)
 * - static u32 in[12] - SURF RNG input state (lines 40)
 * - static u32 out[8] - SURF RNG output buffer (lines 41)
 * - union mysockaddr - Socket address union for IPv4/IPv6 (defined in dnsmasq.h)
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_IDN - Enable legacy IDN support via libidna (domain name internationalization)
 * - HAVE_LIBIDN2 - Enable modern IDN support via libidn2 (preferred over HAVE_IDN)
 * - HAVE_BROKEN_RTC - For embedded systems without RTC, use monotonic clock instead of time()
 * - HAVE_LINUX_NETWORK - Enable Linux-specific optimizations (close_fds via /proc, kernel_version)
 * - HAVE_DNSSEC - Enable DNSSEC-specific name handling in do_rfc1035_name()
 * - HAVE_SOCKADDR_SA_LEN - BSD-style sa_len field in sockaddr (vs. manual size calculation)
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. Functions are generally not thread-safe due to static
 * state in RNG (seed, in, out, outleft) and retry_send(). Designed for single-threaded
 * use within dnsmasq's poll-based event loop. Signal handlers may call dnsmasq_time() which
 * is safe as it only reads system time.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_BROKEN_RTC
#include <sys/times.h>
#endif

#if defined(HAVE_LIBIDN2)
#include <idn2.h>
#elif defined(HAVE_IDN)
#include <idna.h>
#endif

#ifdef HAVE_LINUX_NETWORK
#include <sys/utsname.h>
#endif

/* SURF random number generator */

static u32 seed[32];
static u32 in[12];
static u32 out[8];
static int outleft = 0;

/**
 * @brief Initialize SURF random number generator with entropy from system
 *
 * @detailed Seeds the SURF (Secure Universal Random Function) RNG by reading initial
 * entropy from RANDFILE (/dev/urandom or /dev/random). Must be called once during
 * dnsmasq startup before any calls to rand16(), rand32(), or rand64(). Reads 32+12
 * 32-bit words (176 bytes) of entropy to initialize seed[] and in[] arrays.
 *
 * @return void - Dies with EC_MISC error code if entropy source cannot be read
 *
 * @note Called from main() in dnsmasq.c during daemon initialization
 * @warning Failure to initialize RNG is fatal - dnsmasq cannot operate securely without randomness
 * @see rand16(), rand32(), rand64() for random number generation after initialization
 *
 * EXAMPLE USAGE:
 * @code
 * // In main() during startup
 * rand_init();  // Dies on failure, no error checking needed
 * @endcode
 *
 * RFC COMPLIANCE: N/A
 *
 * SIDE EFFECTS:
 * - Opens and reads from RANDFILE (/dev/urandom)
 * - Initializes static seed[32] and in[12] arrays
 * - Calls die() on failure, terminating the process
 *
 * THREAD SAFETY: Not thread-safe. Must be called once from main thread before any other RNG usage.
 */
void rand_init()
{
  int fd = open(RANDFILE, O_RDONLY);
  
  if (fd == -1 ||
      !read_write(fd, (unsigned char *)&seed, sizeof(seed), 1) ||
      !read_write(fd, (unsigned char *)&in, sizeof(in), 1))
    die(_("failed to seed the random number generator: %s"), NULL, EC_MISC);
  
  close(fd);
}

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

/**
 * @brief Execute SURF algorithm to generate 8 words of random output
 *
 * @detailed Implements the SURF (Secure Universal Random Function) cryptographic random
 * number generator algorithm by Daniel J Bernstein (djbdns-1.05, public domain). Performs
 * 2 loops of 16 rounds each, mixing seed[] and in[] arrays to produce 8 32-bit words in
 * out[]. Uses TEA-like operations with golden ratio constant 0x9e3779b9 for mixing.
 *
 * @return void - Results stored in static out[8] array, outleft set to 8
 *
 * @note Called internally by rand16(), rand32(), rand64() when output buffer exhausted
 * @warning Internal function - do not call directly. Use rand16/32/64 instead.
 * @see rand16(), rand32(), rand64() for public interface
 *
 * RFC COMPLIANCE: N/A (cryptographic algorithm, not protocol)
 *
 * SIDE EFFECTS:
 * - Increments in[] counter (128-bit counter for period 2^128)
 * - Overwrites out[8] with new random values
 * - Sets outleft to 8
 *
 * THREAD SAFETY: Not thread-safe due to static state modification
 */
static void surf(void)
{
  u32 t[12]; u32 x; u32 sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
  for (i = 0;i < 8;++i) out[i] = seed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

/**
 * @brief Generate cryptographically-strong 16-bit random number
 *
 * @detailed Returns a 16-bit unsigned random value using SURF algorithm. Used primarily
 * for DNS query ID randomization to prevent cache poisoning attacks. Automatically calls
 * surf() to refill output buffer when exhausted and increments 128-bit counter.
 *
 * @return Cryptographically-strong 16-bit random value (0-65535)
 *
 * @note Primary use: DNS query ID randomization in forward.c
 * @warning Requires prior rand_init() call during startup
 * @see rand_init() for initialization, rand32() and rand64() for larger random values
 *
 * EXAMPLE USAGE:
 * @code
 * // Generate random DNS query ID
 * unsigned short query_id = rand16();
 * header->id = htons(query_id);
 * @endcode
 *
 * RFC COMPLIANCE: Used for RFC 1035 DNS transaction ID randomization
 *
 * SIDE EFFECTS:
 * - Decrements outleft counter
 * - May call surf() to refill output buffer
 * - May increment in[] counter (via surf())
 *
 * THREAD SAFETY: Not thread-safe due to shared static state (outleft, out[])
 */
unsigned short rand16(void)
{
  if (!outleft) 
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  return (unsigned short) out[--outleft];
}

/**
 * @brief Generate cryptographically-strong 32-bit random number
 *
 * @detailed Returns a full 32-bit unsigned random value using SURF algorithm. Used for
 * source port randomization, lease token generation, and other security-critical random
 * values requiring more entropy than 16 bits.
 *
 * @return Cryptographically-strong 32-bit random value (full u32 range)
 *
 * @note Used for DNS source port randomization and DHCP token generation
 * @warning Requires prior rand_init() call during startup
 * @see rand_init(), rand16(), rand64()
 *
 * EXAMPLE USAGE:
 * @code
 * // Generate random source port (high 16 bits of random u32)
 * u32 rand_val = rand32();
 * unsigned short src_port = 1024 + (rand_val % (65535 - 1024));
 * @endcode
 *
 * RFC COMPLIANCE: Used for RFC 5452 DNS source port randomization
 *
 * SIDE EFFECTS:
 * - Decrements outleft counter
 * - May call surf() to refill output buffer
 * - May increment in[] counter (via surf())
 *
 * THREAD SAFETY: Not thread-safe due to shared static state
 */
u32 rand32(void)
{
 if (!outleft) 
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  return out[--outleft]; 
}

/**
 * @brief Generate cryptographically-strong 64-bit random number
 *
 * @detailed Returns a 64-bit unsigned random value by combining two consecutive 32-bit
 * SURF outputs. Used for generating unique identifiers, IPv6 address randomization, and
 * applications requiring maximum entropy.
 *
 * @return Cryptographically-strong 64-bit random value (full u64 range)
 *
 * @note Uses local static outleft separate from file-scope outleft for 32-bit alignment
 * @warning Requires prior rand_init() call during startup
 * @see rand_init(), rand16(), rand32()
 *
 * EXAMPLE USAGE:
 * @code
 * // Generate random 64-bit host identifier
 * u64 host_id = rand64();
 * setaddr6part(&ipv6_addr, host_id);
 * @endcode
 *
 * RFC COMPLIANCE: Used for RFC 4941 IPv6 privacy extensions (random interface IDs)
 *
 * SIDE EFFECTS:
 * - Decrements local outleft by 2
 * - May call surf() to refill output buffer
 * - May increment in[] counter (via surf())
 *
 * THREAD SAFETY: Not thread-safe due to shared static state and local static outleft
 */
u64 rand64(void)
{
  static int outleft = 0;

  if (outleft < 2)
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  outleft -= 2;

  return (u64)out[outleft+1] + (((u64)out[outleft]) << 32);
}

/**
 * @brief Validate domain name and determine if IDN processing is needed
 *
 * @detailed Checks if domain name is valid according to DNS specifications: labels ≤63 chars,
 * total length ≤MAXDNAME, no control characters, valid dot-separated structure. Also detects
 * if name contains non-ASCII characters or uppercase letters requiring IDN (Internationalized
 * Domain Names) processing. Removes trailing dot if present.
 *
 * @param in Domain name string to validate (modified: trailing dot removed)
 *
 * @return 0 if invalid, 1 if valid ASCII, 2 if requires IDN processing
 * @retval 0 Name is invalid (too long, invalid characters, empty, label >63 chars)
 * @retval 1 Name is valid and ASCII-printable (no IDN processing needed)
 * @retval 2 Name requires IDN processing (contains non-ASCII or uppercase with specific conditions)
 *
 * @note Internal function called by legal_hostname() and canonicalise()
 * @warning Modifies input string by removing trailing dot
 * @see legal_hostname(), canonicalise()
 *
 * EXAMPLE USAGE:
 * @code
 * char domain[] = "example.com.";
 * int result = check_name(domain);  // Returns 1, domain now "example.com"
 * @endcode
 *
 * RFC COMPLIANCE: RFC 1035 domain name syntax, RFC 5890 IDN compatibility
 *
 * SIDE EFFECTS:
 * - Removes trailing dot from input string
 * - Modifies input string in-place
 *
 * THREAD SAFETY: Thread-safe if different threads use different input strings
 */
static int check_name(char *in)
{
  /* remove trailing . 
     also fail empty string and label > 63 chars */
  size_t dotgap = 0, l = strlen(in);
  char c;
  int nowhite = 0;
  int idn_encode = 0;
  int hasuscore = 0;
  int hasucase = 0;
  
  if (l == 0 || l > MAXDNAME) return 0;
  
  if (in[l-1] == '.')
    {
      in[l-1] = 0;
      nowhite = 1;
    }

  for (; (c = *in); in++)
    {
      if (c == '.')
        dotgap = 0;
      else if (++dotgap > MAXLABEL)
        return 0;
      else if (isascii((unsigned char)c) && iscntrl((unsigned char)c)) 
        /* iscntrl only gives expected results for ascii */
        return 0;
      else if (!isascii((unsigned char)c))
#if !defined(HAVE_IDN) && !defined(HAVE_LIBIDN2)
        return 0;
#else
        idn_encode = 1;
#endif
      else if (c != ' ')
        {
          nowhite = 1;
#if defined(HAVE_LIBIDN2) && (!defined(IDN2_VERSION_NUMBER) || IDN2_VERSION_NUMBER < 0x02000003)
          if (c == '_')
            hasuscore = 1;
#else
          (void)hasuscore;
#endif

#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2)
          if (c >= 'A' && c <= 'Z')
            hasucase = 1;
#else
          (void)hasucase;
#endif
        }
    }

  if (!nowhite)
    return 0;

#if defined(HAVE_LIBIDN2) && (!defined(IDN2_VERSION_NUMBER) || IDN2_VERSION_NUMBER < 0x02000003)
  /* Older libidn2 strips underscores, so don't do IDN processing
     if the name has an underscore unless it also has non-ascii characters. */
  idn_encode = idn_encode || (hasucase && !hasuscore);
#else
  idn_encode = idn_encode || hasucase;
#endif

  return (idn_encode) ? 2 : 1;
}

/**
 * @brief Validate hostname against stricter hostname charset rules
 *
 * @detailed Validates that hostname conforms to RFC 952/1123 hostname rules: first label
 * must contain only alphanumeric, hyphen, and underscore characters (hyphens/underscores
 * not at start). Accepts FQDN format but only enforces strict rules on first label, allowing
 * subsequent labels to follow general domain name rules.
 *
 * @param name Hostname or FQDN string to validate (not modified)
 *
 * @return 1 if valid hostname, 0 if invalid
 * @retval 0 Invalid hostname (fails check_name or contains invalid chars in first label)
 * @retval 1 Valid hostname per RFC 952/1123 rules
 *
 * @note Stricter than general domain names - used for DHCP hostnames
 * @warning First character cannot be hyphen or underscore
 * @see check_name() for general domain validation, canonicalise()
 *
 * EXAMPLE USAGE:
 * @code
 * if (legal_hostname("my-server"))
 *     add_dhcp_host("my-server", ipaddr);
 * @endcode
 *
 * RFC COMPLIANCE: RFC 952 (hostname syntax), RFC 1123 (allows leading digit)
 *
 * SIDE EFFECTS: None - read-only operation
 *
 * THREAD SAFETY: Thread-safe (calls check_name which may modify temporary copy)
 */
int legal_hostname(char *name)
{
  char c;
  int first;

  if (!check_name(name))
    return 0;

  for (first = 1; (c = *name); name++, first = 0)
    /* check for legal char a-z A-Z 0-9 - _ . */
    {
      if ((c >= 'A' && c <= 'Z') ||
	  (c >= 'a' && c <= 'z') ||
	  (c >= '0' && c <= '9'))
	continue;

      if (!first && (c == '-' || c == '_'))
	continue;
      
      /* end of hostname part */
      if (c == '.')
	return 1;
      
      return 0;
    }
  
  return 1;
}

/**
 * @brief Canonicalize domain name with optional IDN (Internationalized Domain Names) processing
 *
 * @detailed Converts domain name to canonical form suitable for DNS queries. For ASCII names,
 * returns allocated copy. For names with non-ASCII characters or uppercase (when IDN enabled),
 * converts to ASCII-compatible encoding (ACE) using Punycode per IDNA2008 (libidn2) or IDNA2003
 * (libidna). Returns NULL on invalid names.
 *
 * @param in Input domain name string (may contain non-ASCII if IDN support enabled)
 * @param nomem Pointer to int, set to 1 if memory allocation failed, 0 otherwise (may be NULL)
 *
 * @return Allocated canonical domain name string (caller must free), or NULL on error
 * @retval NULL Invalid domain name or IDN conversion failure
 * @retval non-NULL Allocated string containing canonical ASCII domain name
 *
 * @note Caller must free() returned string if non-NULL
 * @warning Returns NULL if HAVE_IDN/HAVE_LIBIDN2 not defined and name contains non-ASCII
 * @see check_name() for validation, legal_hostname()
 *
 * EXAMPLE USAGE:
 * @code
 * int nomem;
 * char *canon = canonicalise("münchen.de", &nomem);
 * if (canon) {
 *     // Use canon (will be "xn--mnchen-3ya.de")
 *     free(canon);
 * }
 * @endcode
 *
 * RFC COMPLIANCE: RFC 5890 (IDNA2008), RFC 3490 (IDNA2003 for legacy libidna)
 *
 * SIDE EFFECTS:
 * - Allocates memory (must be freed by caller)
 * - May log error to syslog on IDN memory allocation failure
 * - Sets *nomem flag on allocation failure
 *
 * THREAD SAFETY: Thread-safe if libidn2/libidna are thread-safe (generally yes)
 */
char *canonicalise(char *in, int *nomem)
{
  char *ret = NULL;
  int rc;
  
  if (nomem)
    *nomem = 0;
  
  if (!(rc = check_name(in)))
    return NULL;
  
#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2)
  if (rc == 2)
    {
#  ifdef HAVE_LIBIDN2
      rc = idn2_to_ascii_lz(in, &ret, IDN2_NONTRANSITIONAL);
#  else
      rc = idna_to_ascii_lz(in, &ret, 0);
#  endif
      if (rc != IDNA_SUCCESS)
	{
	  if (ret)
	    free(ret);
	  
	  if (nomem && (rc == IDNA_MALLOC_ERROR || rc == IDNA_DLOPEN_ERROR))
	    {
	      my_syslog(LOG_ERR, _("failed to allocate memory"));
	      *nomem = 1;
	    }
	  
	  return NULL;
	}
      
      return ret;
    }
#else
  (void)rc;
#endif
  
  if ((ret = whine_malloc(strlen(in)+1)))
    strcpy(ret, in);
  else if (nomem)
    *nomem = 1;

  return ret;
}

/**
 * @brief Encode domain name in RFC 1035 wire format with length-prefixed labels
 *
 * @detailed Converts dot-separated domain name string to DNS wire format where each label
 * is prefixed by its length byte (e.g., "example.com" → \x07example\x03com). Handles optional
 * DNSSEC NAME_ESCAPE sequences for special characters. Stops at limit pointer if provided.
 *
 * @param p Pointer to output buffer position (updated to point after encoded name)
 * @param sval Input domain name string (dot-separated labels)
 * @param limit Optional buffer limit pointer, or NULL for no limit check
 *
 * @return Updated pointer past encoded name, or NULL if limit exceeded
 * @retval NULL Buffer limit exceeded during encoding
 * @retval non-NULL Pointer to byte after encoded name (ready for next field)
 *
 * @note Does NOT write terminating zero byte - caller must add if needed
 * @warning No bounds checking if limit is NULL - ensure buffer is large enough
 * @see Used in DNS packet construction throughout dnsmasq
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char packet[512];
 * unsigned char *p = packet;
 * p = do_rfc1035_name(p, "example.com", packet + sizeof(packet));
 * if (p) *p++ = 0;  // Add terminating zero
 * @endcode
 *
 * RFC COMPLIANCE: RFC 1035 Section 3.1 (Name space definitions and DNS message format)
 *
 * SIDE EFFECTS:
 * - Writes to output buffer via p pointer
 * - Updates p pointer position
 *
 * THREAD SAFETY: Thread-safe if different threads use different buffers
 */
unsigned char *do_rfc1035_name(unsigned char *p, char *sval, char *limit)
{
  int j;
  
  while (sval && *sval)
    {
      unsigned char *cp = p++;

      if (limit && p > (unsigned char*)limit)
        return NULL;

      for (j = 0; *sval && (*sval != '.'); sval++, j++)
	{
          if (limit && p + 1 > (unsigned char*)limit)
            return NULL;

#ifdef HAVE_DNSSEC
	  if (option_bool(OPT_DNSSEC_VALID) && *sval == NAME_ESCAPE)
	    *p++ = (*(++sval))-1;
	  else
#endif		
	    *p++ = *sval;
	}
      
      *cp  = j;
      if (*sval)
	sval++;
    }
  
  return p;
}

/**
 * @brief Allocate zero-initialized memory or die on failure
 *
 * @detailed Fatal memory allocator for startup and critical paths where allocation failure
 * cannot be recovered. Allocates memory via calloc() (zeroed) and calls die() with EC_NOMEM
 * if allocation fails, immediately terminating dnsmasq.
 *
 * @param size Number of bytes to allocate
 *
 * @return Pointer to allocated zero-initialized memory (never NULL)
 *
 * @note Used during startup when memory exhaustion is fatal
 * @warning Never returns NULL - calls die() on failure, terminating process
 * @see whine_malloc() for non-fatal allocation, die() for error termination
 *
 * EXAMPLE USAGE:
 * @code
 * struct server *srv = safe_malloc(sizeof(struct server));
 * // srv is guaranteed non-NULL and zeroed
 * @endcode
 *
 * RFC COMPLIANCE: N/A
 *
 * SIDE EFFECTS:
 * - Allocates heap memory
 * - Terminates process if allocation fails
 *
 * THREAD SAFETY: Thread-safe (calloc is thread-safe)
 */
void *safe_malloc(size_t size)
{
  void *ret = calloc(1, size);
  
  if (!ret)
    die(_("could not get memory"), NULL, EC_NOMEM);
      
  return ret;
}

/**
 * @brief Copy string ensuring destination is always null-terminated
 *
 * @detailed Safe alternative to strncpy() that guarantees null-termination. Similar to BSD
 * strlcpy() but available on all platforms. Copies up to size-1 bytes from src to dest,
 * always null-terminating dest (unlike strncpy which may not terminate if src ≥ size).
 *
 * @param dest Destination buffer (must be at least size bytes)
 * @param src Source string to copy
 * @param size Size of dest buffer in bytes
 *
 * @return void
 *
 * @note Replacement for strlcpy() on platforms without it
 * @warning size must be >0 and dest must be at least size bytes
 * @see strncpy() (unsafe without manual termination)
 *
 * EXAMPLE USAGE:
 * @code
 * char buffer[64];
 * safe_strncpy(buffer, long_hostname, sizeof(buffer));
 * // buffer is guaranteed null-terminated
 * @endcode
 *
 * RFC COMPLIANCE: N/A
 *
 * SIDE EFFECTS: Writes to dest buffer
 *
 * THREAD SAFETY: Thread-safe if dest and src don't overlap
 */
void safe_strncpy(char *dest, const char *src, size_t size)
{
  if (size != 0)
    {
      dest[size-1] = '\0';
      strncpy(dest, src, size-1);
    }
}

/**
 * @brief Create pipe with non-blocking options or die on failure
 *
 * @detailed Creates pipe via pipe() system call and optionally sets non-blocking mode on
 * read and/or write ends via fix_fd(). Dies with EC_MISC if pipe creation or fcntl fails.
 * Used for signal self-pipe pattern and inter-process communication.
 *
 * @param fd Array of 2 ints to receive pipe file descriptors [read_fd, write_fd]
 * @param read_noblock If non-zero, set read end to non-blocking via fix_fd()
 *
 * @return void - Dies on failure, never returns with error
 *
 * @note Write end always set non-blocking via fix_fd()
 * @warning Never returns with error - calls die() on failure
 * @see fix_fd() for non-blocking setup, used in signal self-pipe (dnsmasq.c)
 *
 * EXAMPLE USAGE:
 * @code
 * int pipefd[2];
 * safe_pipe(pipefd, 1);  // Both ends non-blocking
 * // pipefd[0] is read end, pipefd[1] is write end
 * @endcode
 *
 * RFC COMPLIANCE: N/A
 *
 * SIDE EFFECTS:
 * - Creates pipe (consumes 2 file descriptors)
 * - Sets non-blocking mode on file descriptors
 * - May terminate process on failure
 *
 * THREAD SAFETY: Thread-safe (system calls are thread-safe)
 */
void safe_pipe(int *fd, int read_noblock)
{
  if (pipe(fd) == -1 || 
      !fix_fd(fd[1]) ||
      (read_noblock && !fix_fd(fd[0])))
    die(_("cannot create pipe: %s"), NULL, EC_MISC);
}

/**
 * @brief Allocate zero-initialized memory with syslog warning on failure
 *
 * @detailed Non-fatal memory allocator for runtime operations where allocation failure can
 * be handled gracefully. Allocates via calloc() (zeroed) and logs error to syslog if allocation
 * fails, but returns NULL allowing caller to handle error. Preferred over safe_malloc() for
 * non-critical allocations.
 *
 * @param size Number of bytes to allocate
 *
 * @return Pointer to allocated zero-initialized memory, or NULL on failure
 * @retval NULL Memory allocation failed (error logged to syslog)
 * @retval non-NULL Pointer to allocated zeroed memory
 *
 * @note Logs allocation failure to syslog but does not terminate
 * @warning Caller must check for NULL return and handle allocation failure
 * @see safe_malloc() for fatal allocation, used throughout dnsmasq for dynamic structures
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = whine_malloc(sizeof(struct dhcp_lease));
 * if (!lease) return 0;  // Handle allocation failure
 * @endcode
 *
 * RFC COMPLIANCE: N/A
 *
 * SIDE EFFECTS:
 * - Allocates heap memory if successful
 * - Logs to syslog on failure
 *
 * THREAD SAFETY: Thread-safe (calloc and my_syslog are thread-safe)
 */
void *whine_malloc(size_t size)
{
  void *ret = calloc(1, size);

  if (!ret)
    my_syslog(LOG_ERR, _("failed to allocate %d bytes"), (int) size);
  
  return ret;
}

/**
 * @brief Compare two socket addresses for equality (IPv4 or IPv6)
 *
 * @detailed Compares two union mysockaddr structures for complete equality including address
 * family, IP address, port number, and (for IPv6) scope ID. Returns 1 only if all fields
 * match exactly. Used for detecting duplicate servers and comparing source addresses.
 *
 * @param s1 First socket address to compare
 * @param s2 Second socket address to compare
 *
 * @return 1 if addresses are identical, 0 if different
 * @retval 0 Different families, addresses, ports, or scope IDs
 * @retval 1 Complete match (family, address, port, and scope)
 *
 * @note For IPv6, scope_id must also match
 * @warning Only handles AF_INET and AF_INET6 families
 * @see sa_len() for size calculation, prettyprint_addr() for display
 *
 * EXAMPLE USAGE:
 * @code
 * if (sockaddr_isequal(&source_addr, &expected_addr))
 *     process_reply_from_known_server(packet);
 * @endcode
 *
 * RFC COMPLIANCE: N/A (address comparison utility)
 *
 * SIDE EFFECTS: None - read-only comparison
 *
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
int sockaddr_isequal(const union mysockaddr *s1, const union mysockaddr *s2)
{
  if (s1->sa.sa_family == s2->sa.sa_family)
    { 
      if (s1->sa.sa_family == AF_INET &&
	  s1->in.sin_port == s2->in.sin_port &&
	  s1->in.sin_addr.s_addr == s2->in.sin_addr.s_addr)
	return 1;
      
      if (s1->sa.sa_family == AF_INET6 &&
	  s1->in6.sin6_port == s2->in6.sin6_port &&
	  s1->in6.sin6_scope_id == s2->in6.sin6_scope_id &&
	  IN6_ARE_ADDR_EQUAL(&s1->in6.sin6_addr, &s2->in6.sin6_addr))
	return 1;
    }
  return 0;
}

/**
 * @brief Calculate socket address structure size for IPv4 or IPv6
 *
 * @detailed Returns size in bytes of sockaddr structure depending on address family. On BSD
 * systems with HAVE_SOCKADDR_SA_LEN, uses sa_len field. Otherwise calculates size based on
 * sa_family (sizeof(sockaddr_in6) for AF_INET6, sizeof(sockaddr_in) for AF_INET).
 *
 * @param addr Pointer to socket address union
 *
 * @return Size in bytes of the socket address structure
 * @retval sizeof(sockaddr_in6) For IPv6 addresses (28 bytes typically)
 * @retval sizeof(sockaddr_in) For IPv4 addresses (16 bytes typically)
 *
 * @note Uses BSD sa_len field if HAVE_SOCKADDR_SA_LEN defined
 * @warning Assumes addr->sa.sa_family is AF_INET or AF_INET6
 * @see sockaddr_isequal() for comparison, used in bind(), sendto(), recvfrom() calls
 *
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr dest;
 * dest.sa.sa_family = AF_INET;
 * sendto(fd, packet, len, 0, &dest.sa, sa_len(&dest));
 * @endcode
 *
 * RFC COMPLIANCE: N/A
 *
 * SIDE EFFECTS: None - read-only size calculation
 *
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
int sa_len(union mysockaddr *addr)
{
#ifdef HAVE_SOCKADDR_SA_LEN
  return addr->sa.sa_len;
#else
  if (addr->sa.sa_family == AF_INET6)
    return sizeof(addr->in6);
  else
    return sizeof(addr->in); 
#endif
}

/**
 * @brief Compare two hostnames lexicographically (case-insensitive, locale-independent)
 *
 * @detailed Performs case-insensitive hostname comparison without locale dependencies (unlike
 * strcasecmp which may be affected by LC_COLLATE). Converts A-Z to a-z during comparison.
 * Returns <0 if a < b, 0 if equal, >0 if a > b. Used for sorting hostname lists.
 *
 * @param a First hostname string
 * @param b Second hostname string
 *
 * @return Comparison result: negative if a<b, 0 if equal, positive if a>b
 * @retval -1 Hostname a sorts before hostname b
 * @retval 0 Hostnames are equal (case-insensitive)
 * @retval 1 Hostname a sorts after hostname b
 *
 * @note Locale-independent to avoid LC_COLLATE interference
 * @warning Does not handle IDN or non-ASCII characters
 * @see hostname_isequal() for equality test, hostname_issubdomain() for hierarchy test
 *
 * EXAMPLE USAGE:
 * @code
 * if (hostname_order("example.com", "sub.example.com") < 0)
 *     // "example.com" sorts before "sub.example.com"
 * @endcode
 *
 * RFC COMPLIANCE: RFC 1035 (DNS names are case-insensitive)
 *
 * SIDE EFFECTS: None - read-only comparison
 *
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
int hostname_order(const char *a, const char *b)
{
  unsigned int c1, c2;
  
  do {
    c1 = (unsigned char) *a++;
    c2 = (unsigned char) *b++;
    
    if (c1 >= 'A' && c1 <= 'Z')
      c1 += 'a' - 'A';
    if (c2 >= 'A' && c2 <= 'Z')
      c2 += 'a' - 'A';
    
    if (c1 < c2)
      return -1;
    else if (c1 > c2)
      return 1;
    
  } while (c1);
  
  return 0;
}

/**
 * @brief Test hostname equality (case-insensitive)
 *
 * @detailed Simple wrapper around hostname_order() returning 1 if hostnames are equal
 * (case-insensitive), 0 otherwise. More readable than "hostname_order(a,b) == 0" in code.
 *
 * @param a First hostname string
 * @param b Second hostname string
 *
 * @return 1 if hostnames equal (case-insensitive), 0 if different
 * @retval 0 Hostnames differ
 * @retval 1 Hostnames are equal (ignoring case)
 *
 * @note Wrapper for hostname_order() == 0
 * @see hostname_order() for comparison implementation
 *
 * EXAMPLE USAGE:
 * @code
 * if (hostname_isequal("Example.COM", "example.com"))
 *     // Hostnames match despite different case
 * @endcode
 *
 * RFC COMPLIANCE: RFC 1035 (DNS names are case-insensitive)
 *
 * SIDE EFFECTS: None - read-only comparison
 *
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
int hostname_isequal(const char *a, const char *b)
{
  return hostname_order(a, b) == 0;
}

/**
 * @brief Test if b is equal to or subdomain of a (case-insensitive)
 *
 * @detailed Checks DNS hierarchy relationship by comparing hostnames from right to left.
 * Returns 2 if hostnames are equal, 1 if b is proper subdomain of a (ends with ".a"), 0 if
 * unrelated. For example, "www.example.com" is subdomain of "example.com".
 *
 * @param a Parent domain name string
 * @param b Domain name to test against parent
 *
 * @return Relationship code: 0=unrelated, 1=subdomain, 2=equal
 * @retval 0 b is not equal to and not subdomain of a
 * @retval 1 b is proper subdomain of a (e.g., "www.example.com" is subdomain of "example.com")
 * @retval 2 b equals a (same domain, case-insensitive)
 *
 * @note Compares from right to left (domain hierarchy)
 * @warning Returns 0 if a is empty or longer than b
 * @see hostname_isequal() for simple equality, hostname_order() for lexicographic comparison
 *
 * EXAMPLE USAGE:
 * @code
 * int rel = hostname_issubdomain("example.com", "www.example.com");
 * if (rel == 1)  // www.example.com is subdomain
 *     apply_domain_policy("example.com");
 * @endcode
 *
 * RFC COMPLIANCE: RFC 1035 (DNS hierarchical namespace)
 *
 * SIDE EFFECTS: None - read-only comparison
 *
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
int hostname_issubdomain(char *a, char *b)
{
  char *ap, *bp;
  unsigned int c1, c2;
  
  /* move to the end */
  for (ap = a; *ap; ap++); 
  for (bp = b; *bp; bp++);

  /* a shorter than b or a empty. */
  if ((bp - b) < (ap - a) || ap == a)
    return 0;

  do
    {
      c1 = (unsigned char) *(--ap);
      c2 = (unsigned char) *(--bp);
  
       if (c1 >= 'A' && c1 <= 'Z')
	 c1 += 'a' - 'A';
       if (c2 >= 'A' && c2 <= 'Z')
	 c2 += 'a' - 'A';

       if (c1 != c2)
	 return 0;
    } while (ap != a);

  if (bp == b)
    return 2;

  if (*(--bp) == '.')
    return 1;

  return 0;
}

/**
 * @brief Get current time (real time or monotonic for embedded systems)
 *
 * @detailed Returns current time in seconds. On systems with HAVE_BROKEN_RTC (embedded systems
 * without real-time clock), uses monotonic clock via clock_gettime(CLOCK_MONOTONIC) which never
 * goes backwards. On normal systems, uses standard time(NULL) returning Unix epoch time.
 *
 * @return Current time in seconds (Unix epoch or monotonic seconds since boot)
 *
 * @note Uses monotonic clock if HAVE_BROKEN_RTC defined (embedded systems)
 * @warning On HAVE_BROKEN_RTC systems, time is relative to boot, not absolute Unix time
 * @see Used throughout dnsmasq for lease expiry, cache TTL, retry timeouts
 *
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * lease->expires = now + lease_time;
 * @endcode
 *
 * RFC COMPLIANCE: N/A
 *
 * SIDE EFFECTS:
 * - Calls die() if clock_gettime() fails (HAVE_BROKEN_RTC only)
 *
 * THREAD SAFETY: Thread-safe (system calls are thread-safe)
 */
time_t dnsmasq_time(void)
{
#ifdef HAVE_BROKEN_RTC
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    die(_("cannot read monotonic clock: %s"), NULL, EC_MISC);

  return ts.tv_sec;
#else
  return time(NULL);
#endif
}

/**
 * @brief Calculate CIDR prefix length from IPv4 netmask
 *
 * @detailed Counts number of consecutive 1-bits in netmask from most significant bit to determine
 * CIDR prefix length (e.g., 255.255.255.0 = /24). Counts trailing 0-bits and subtracts from 32.
 *
 * @param mask IPv4 netmask in network byte order
 *
 * @return CIDR prefix length (0-32)
 *
 * @note Assumes contiguous netmask (no holes in bit pattern)
 * @warning Non-contiguous netmasks will give incorrect results
 * @see is_same_net() for network comparison, is_same_net_prefix() for prefix-based comparison
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr mask;
 * inet_pton(AF_INET, "255.255.255.0", &mask);
 * int prefix = netmask_length(mask);  // Returns 24
 * @endcode
 *
 * RFC COMPLIANCE: RFC 4632 (CIDR notation)
 *
 * SIDE EFFECTS: None - read-only calculation
 *
 * THREAD SAFETY: Thread-safe (pure calculation)
 */
int netmask_length(struct in_addr mask)
{
  int zero_count = 0;

  while (0x0 == (mask.s_addr & 0x1) && zero_count < 32) 
    {
      mask.s_addr >>= 1;
      zero_count++;
    }
  
  return 32 - zero_count;
}

/**
 * @brief Test if two IPv4 addresses are in same network (with netmask)
 *
 * @detailed Applies netmask to both addresses and compares result. Returns 1 if addresses
 * are in the same network segment (i.e., (a & mask) == (b & mask)).
 *
 * @param a First IPv4 address
 * @param b Second IPv4 address
 * @param mask Network mask to apply
 *
 * @return 1 if same network, 0 if different networks
 * @retval 0 Addresses in different network segments
 * @retval 1 Addresses in same network segment
 *
 * @note Used for DHCP range validation and routing decisions
 * @see is_same_net_prefix() for CIDR prefix version, is_same_net6() for IPv6
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr addr1, addr2, mask;
 * // addr1=192.168.1.10, addr2=192.168.1.20, mask=255.255.255.0
 * if (is_same_net(addr1, addr2, mask))
 *     // Same /24 network
 * @endcode
 *
 * RFC COMPLIANCE: N/A (network comparison utility)
 *
 * SIDE EFFECTS: None - read-only comparison
 *
 * THREAD SAFETY: Thread-safe (pure calculation)
 */
int is_same_net(struct in_addr a, struct in_addr b, struct in_addr mask)
{
  return (a.s_addr & mask.s_addr) == (b.s_addr & mask.s_addr);
}

/**
 * @brief Test if two IPv4 addresses are in same network (with CIDR prefix)
 *
 * @detailed Convenience wrapper that constructs netmask from CIDR prefix length and calls
 * is_same_net(). For example, prefix=24 creates mask 255.255.255.0.
 *
 * @param a First IPv4 address
 * @param b Second IPv4 address
 * @param prefix CIDR prefix length (0-32)
 *
 * @return 1 if same network, 0 if different networks
 * @retval 0 Addresses in different network segments
 * @retval 1 Addresses in same network segment
 *
 * @note More convenient than is_same_net() when working with CIDR notation
 * @see is_same_net() for netmask version, is_same_net6() for IPv6
 *
 * EXAMPLE USAGE:
 * @code
 * if (is_same_net_prefix(client_addr, pool_addr, 24))
 *     // Client in same /24 as DHCP pool
 * @endcode
 *
 * RFC COMPLIANCE: RFC 4632 (CIDR notation)
 *
 * SIDE EFFECTS: None - read-only comparison
 *
 * THREAD SAFETY: Thread-safe (pure calculation)
 */
int is_same_net_prefix(struct in_addr a, struct in_addr b, int prefix)
{
  struct in_addr mask;

  mask.s_addr = htonl(~((1 << (32 - prefix)) - 1));

  return is_same_net(a, b, mask);
}

/**
 * @brief Test if two IPv6 addresses share same prefix
 *
 * @detailed Compares first prefixlen bits of two IPv6 addresses. First compares full bytes
 * (prefixlen/8), then compares remaining bits in partial byte if any. Used for DHCPv6 range
 * validation and IPv6 routing decisions.
 *
 * @param a First IPv6 address pointer
 * @param b Second IPv6 address pointer
 * @param prefixlen IPv6 prefix length in bits (0-128)
 *
 * @return 1 if addresses share prefix, 0 if different prefixes
 * @retval 0 Addresses have different prefixes
 * @retval 1 Addresses share same prefix of specified length
 *
 * @note More efficient than generating mask - compares bytes then partial byte
 * @see is_same_net() for IPv4 equivalent, addr6part() for extracting host portion
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr addr1, addr2;
 * // addr1=2001:db8::1, addr2=2001:db8::2, prefix=64
 * if (is_same_net6(&addr1, &addr2, 64))
 *     // Same /64 network
 * @endcode
 *
 * RFC COMPLIANCE: RFC 4291 (IPv6 addressing architecture)
 *
 * SIDE EFFECTS: None - read-only comparison
 *
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
int is_same_net6(struct in6_addr *a, struct in6_addr *b, int prefixlen)
{
  int pfbytes = prefixlen >> 3;
  int pfbits = prefixlen & 7;

  if (memcmp(&a->s6_addr, &b->s6_addr, pfbytes) != 0)
    return 0;

  if (pfbits == 0 ||
      (a->s6_addr[pfbytes] >> (8 - pfbits) == b->s6_addr[pfbytes] >> (8 - pfbits)))
    return 1;

  return 0;
}

/**
 * @brief Extract least significant 64 bits (host part) of IPv6 address
 *
 * @detailed Extracts lower 64 bits (bytes 8-15) of IPv6 address as u64 value. Used for
 * manipulating interface identifiers in IPv6 addresses (host portion in /64 networks) for
 * SLAAC, DHCPv6, and privacy extensions.
 *
 * @param addr Pointer to IPv6 address structure
 *
 * @return Lower 64 bits of IPv6 address as u64
 *
 * @note Typically used for /64 networks where lower 64 bits are host identifier
 * @see setaddr6part() for setting host portion, used in SLAAC and DHCPv6
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr ipv6_addr;
 * u64 interface_id = addr6part(&ipv6_addr);
 * u64 new_id = rand64();
 * setaddr6part(&ipv6_addr, new_id);  // Randomize interface ID
 * @endcode
 *
 * RFC COMPLIANCE: RFC 4291 (IPv6 addressing - interface identifier)
 *
 * SIDE EFFECTS: None - read-only extraction
 *
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
u64 addr6part(struct in6_addr *addr)
{
  int i;
  u64 ret = 0;

  for (i = 8; i < 16; i++)
    ret = (ret << 8) + addr->s6_addr[i];

  return ret;
}

/**
 * @brief Set least significant 64 bits (host part) of IPv6 address
 *
 * @detailed Writes u64 value into lower 64 bits (bytes 8-15) of IPv6 address, leaving upper
 * 64 bits (network prefix) unchanged. Used for SLAAC address construction, DHCPv6 address
 * allocation, and privacy extensions where host identifier is derived or randomized.
 *
 * @param addr Pointer to IPv6 address structure to modify
 * @param host 64-bit value to write as host portion
 *
 * @return void
 *
 * @note Preserves upper 64 bits (network prefix), modifies only bytes 8-15
 * @warning Modifies addr in-place
 * @see addr6part() for extracting host portion, used in SLAAC and DHCPv6 address assignment
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr ipv6_addr;
 * // ipv6_addr has network prefix 2001:db8::/64
 * u64 interface_id = calculate_eui64_from_mac(mac_address);
 * setaddr6part(&ipv6_addr, interface_id);
 * // Now ipv6_addr = 2001:db8::EUI-64-based-ID
 * @endcode
 *
 * RFC COMPLIANCE: RFC 4291 (IPv6 addressing), RFC 4862 (SLAAC)
 *
 * SIDE EFFECTS: Modifies bytes 8-15 of addr
 *
 * THREAD SAFETY: Thread-safe if different threads use different addr pointers
 */
void setaddr6part(struct in6_addr *addr, u64 host)
{
  int i;

  for (i = 15; i >= 8; i--)
    {
      addr->s6_addr[i] = host;
      host = host >> 8;
    }
}

/**
 * @brief Format socket address as human-readable string with optional scope
 *
 * @detailed Converts union mysockaddr (IPv4 or IPv6) to string representation using inet_ntop().
 * For IPv6 link-local addresses with scope_id, appends "%interface_name" (e.g., "fe80::1%eth0").
 * Returns port number extracted from address. Used for logging and display.
 *
 * @param addr Pointer to socket address union (IPv4 or IPv6)
 * @param buf Output buffer for formatted address string (must be ≥ADDRSTRLEN bytes)
 *
 * @return Port number from address in host byte order (ntohs applied)
 *
 * @note Buffer must be at least ADDRSTRLEN bytes (defined in dnsmasq.h)
 * @warning Buffer overflow if buf < ADDRSTRLEN - caller must ensure adequate size
 * @see Used throughout dnsmasq for logging addresses, inet_ntop() for conversion
 *
 * EXAMPLE USAGE:
 * @code
 * char addrbuf[ADDRSTRLEN];
 * int port = prettyprint_addr(&source_addr, addrbuf);
 * my_syslog(LOG_INFO, "query from %s#%d", addrbuf, port);
 * @endcode
 *
 * RFC COMPLIANCE: RFC 4007 (IPv6 scoped address format with % notation)
 *
 * SIDE EFFECTS:
 * - Writes to buf (ADDRSTRLEN bytes)
 * - Calls if_indextoname() for IPv6 scope resolution
 *
 * THREAD SAFETY: Thread-safe if different threads use different buf pointers
 */
int prettyprint_addr(union mysockaddr *addr, char *buf)
{
  int port = 0;
  
  if (addr->sa.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &addr->in.sin_addr, buf, ADDRSTRLEN);
      port = ntohs(addr->in.sin_port);
    }
  else if (addr->sa.sa_family == AF_INET6)
    {
      char name[IF_NAMESIZE];
      inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, ADDRSTRLEN);
      if (addr->in6.sin6_scope_id != 0 &&
	  if_indextoname(addr->in6.sin6_scope_id, name) &&
	  strlen(buf) + strlen(name) + 2 <= ADDRSTRLEN)
	{
	  strcat(buf, "%");
	  strcat(buf, name);
	}
      port = ntohs(addr->in6.sin6_port);
    }
  
  return port;
}

/**
 * @brief Format time interval as human-readable string (days/hours/minutes/seconds)
 *
 * @detailed Converts seconds into human-friendly format with units: 1d2h3m4s (days, hours,
 * minutes, seconds). Special value 0xffffffff (infinite) displayed as "infinite". Omits zero
 * components (e.g., "2h30m" if no days or seconds). Used for DHCP lease time display.
 *
 * @param buf Output buffer for formatted time string (must be sufficient for max "4294967295d23h59m59s")
 * @param t Time in seconds (or 0xffffffff for infinite)
 *
 * @return void
 *
 * @note 0xffffffff is special value meaning "infinite" (often for static DHCP leases)
 * @warning Buffer must be large enough - recommend 64 bytes minimum
 * @see Used in DHCP lease logging and status display
 *
 * EXAMPLE USAGE:
 * @code
 * char timebuf[64];
 * prettyprint_time(timebuf, 7322);  // Result: "2h2m2s"
 * my_syslog(LOG_INFO, "lease time: %s", timebuf);
 * @endcode
 *
 * RFC COMPLIANCE: N/A (display formatting utility)
 *
 * SIDE EFFECTS: Writes to buf
 *
 * THREAD SAFETY: Thread-safe if different threads use different buf pointers
 */
void prettyprint_time(char *buf, unsigned int t)
{
  if (t == 0xffffffff)
    sprintf(buf, _("infinite"));
  else
    {
      unsigned int x, p = 0;
       if ((x = t/86400))
	p += sprintf(&buf[p], "%ud", x);
       if ((x = (t/3600)%24))
	p += sprintf(&buf[p], "%uh", x);
      if ((x = (t/60)%60))
	p += sprintf(&buf[p], "%um", x);
      if ((x = t%60))
	sprintf(&buf[p], "%us", x);
    }
}

/**
 * @brief Parse colon/hyphen-separated hexadecimal string (MAC addresses, hex data)
 *
 * @detailed Parses hex string like "01:23:45:67:89:ab" or "01-23-45-67-89-ab" into byte array.
 * Supports wildcard "*" for any byte (tracked in wildcard_mask bitmask). Optionally extracts
 * leading hex value before first hyphen as mac_type (for DHCP client-id type). Returns number
 * of bytes parsed or -1 on invalid characters.
 *
 * @param in Input hex string (may be modified - colons/hyphens replaced with nulls)
 * @param out Output byte array (may equal in for in-place conversion)
 * @param maxlen Maximum bytes to parse, or -1 for unlimited
 * @param wildcard_mask Pointer to unsigned int to receive wildcard bitmask, or NULL (bit set = wildcard)
 * @param mac_type Pointer to int to receive leading type value (before first hyphen), or NULL
 *
 * @return Number of bytes parsed (0-maxlen), or -1 on invalid characters
 * @retval -1 Invalid characters found (not hex, colon, hyphen, space, or asterisk)
 * @retval ≥0 Number of bytes successfully parsed into out
 *
 * @note Modifies in string by replacing separators with nulls during parsing
 * @warning in and out may alias (same pointer) - supports in-place conversion
 * @see Used for DHCP hardware address parsing and hex data parsing
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac[6];
 * unsigned int wildcard;
 * char hex_str[] = "01:*:03:04:05:06";
 * int len = parse_hex(hex_str, mac, 6, &wildcard, NULL);
 * // len=6, wildcard=0x2 (bit 1 set for 2nd byte), mac={0x01,?,0x03,0x04,0x05,0x06}
 * @endcode
 *
 * RFC COMPLIANCE: Used for RFC 2132 DHCP hardware address parsing
 *
 * SIDE EFFECTS:
 * - Modifies in string by replacing separators with null bytes
 * - Writes to out array
 * - Sets *wildcard_mask if provided
 * - Sets *mac_type if provided
 *
 * THREAD SAFETY: Thread-safe if different threads use different buffers
 */
int parse_hex(char *in, unsigned char *out, int maxlen, 
	      unsigned int *wildcard_mask, int *mac_type)
{
  int done = 0, mask = 0, i = 0;
  char *r;
    
  if (mac_type)
    *mac_type = 0;
  
  while (!done && (maxlen == -1 || i < maxlen))
    {
      for (r = in; *r != 0 && *r != ':' && *r != '-' && *r != ' '; r++)
	if (*r != '*' && !isxdigit((unsigned char)*r))
	  return -1;
      
      if (*r == 0)
	done = 1;
      
      if (r != in )
	{
	  if (*r == '-' && i == 0 && mac_type)
	   {
	      *r = 0;
	      *mac_type = strtol(in, NULL, 16);
	      mac_type = NULL;
	   }
	  else
	    {
	      *r = 0;
	      if (strcmp(in, "*") == 0)
		{
		  mask = (mask << 1) | 1;
		  i++;
		}
	      else
		{
		  int j, bytes = (1 + (r - in))/2;
		  for (j = 0; j < bytes; j++)
		    { 
		      char sav;
		      if (j < bytes - 1)
			{
			  sav = in[(j+1)*2];
			  in[(j+1)*2] = 0;
			}
		      /* checks above allow mix of hexdigit and *, which
			 is illegal. */
		      if (strchr(&in[j*2], '*'))
			return -1;
		      out[i] = strtol(&in[j*2], NULL, 16);
		      mask = mask << 1;
		      if (++i == maxlen)
			break; 
		      if (j < bytes - 1)
			in[(j+1)*2] = sav;
		    }
		}
	    }
	}
      in = r+1;
    }
  
  if (wildcard_mask)
    *wildcard_mask = mask;

  return i;
}

/**
 * @brief Compare byte arrays with wildcard mask support
 *
 * @detailed Compares arrays a and b byte-by-byte, skipping comparison where mask bit is 1
 * (wildcard). Returns 0 if any non-wildcard bytes differ, otherwise returns (number of
 * matching non-wildcard bytes)+1. Used for DHCP hardware address matching with wildcards.
 *
 * @param a First byte array
 * @param b Second byte array
 * @param len Length of arrays in bytes
 * @param mask Wildcard bitmask (LSB=last byte, bit 1=wildcard/skip comparison)
 *
 * @return 0 for mismatch, or (count of matched bytes)+1 for match
 * @retval 0 Arrays differ in at least one non-wildcard byte
 * @retval ≥1 All non-wildcard bytes match, return value = (matched count)+1
 *
 * @note Returns count+1 (not count) to distinguish zero matches from mismatch
 * @warning Iterates from len-1 to 0 (LSB of mask corresponds to last byte)
 * @see parse_hex() for generating wildcard_mask, used in DHCP config matching
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac1[] = {0x01,0x02,0x03,0x04,0x05,0x06};
 * unsigned char mac2[] = {0x01,0xFF,0x03,0x04,0x05,0x06};
 * unsigned int mask = 0x2;  // Wildcard 2nd byte (bit 1)
 * int result = memcmp_masked(mac1, mac2, 6, mask);
 * // Returns 6 (5 matched bytes + 1), since 2nd byte ignored
 * @endcode
 *
 * RFC COMPLIANCE: N/A (wildcard matching utility for DHCP)
 *
 * SIDE EFFECTS: None - read-only comparison
 *
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
int memcmp_masked(unsigned char *a, unsigned char *b, int len, unsigned int mask)
{
  int i, count;
  for (count = 1, i = len - 1; i >= 0; i--, mask = mask >> 1)
    if (!(mask & 1))
      {
	if (a[i] == b[i])
	  count++;
	else
	  return 0;
      }
  return count;
}

/**
 * @brief Expand iovec buffer to at least specified size (may reallocate)
 *
 * @detailed Ensures iovec buffer is at least 'size' bytes. If current iov_len < size, allocates
 * new buffer via whine_malloc(), copies existing data if present, frees old buffer, and updates
 * iov pointers. Returns 1 on success, 0 on allocation failure (sets errno=ENOMEM).
 *
 * @param iov Pointer to struct iovec to expand (iov_base and iov_len updated)
 * @param size Required minimum size in bytes
 *
 * @return 1 on success (buffer adequate or successfully expanded), 0 on allocation failure
 * @retval 0 Memory allocation failed (errno=ENOMEM)
 * @retval 1 Buffer is adequate or successfully expanded to requested size
 *
 * @note May copy buffer if expansion needed - invalidates pointers into old iov_base
 * @warning Sets errno=ENOMEM on failure, iov unchanged on allocation failure
 * @see whine_malloc() for allocation, used in packet handling for dynamic resizing
 *
 * EXAMPLE USAGE:
 * @code
 * struct iovec iov = {NULL, 0};
 * if (!expand_buf(&iov, 1024))
 *     return -1;  // Allocation failed
 * // iov.iov_base now points to ≥1024 byte buffer
 * @endcode
 *
 * RFC COMPLIANCE: N/A (buffer management utility)
 *
 * SIDE EFFECTS:
 * - May allocate new buffer via whine_malloc()
 * - May free old buffer
 * - Updates iov->iov_base and iov->iov_len
 * - Sets errno on failure
 *
 * THREAD SAFETY: Thread-safe if different threads use different iov pointers
 */
int expand_buf(struct iovec *iov, size_t size)
{
  void *new;

  if (size <= (size_t)iov->iov_len)
    return 1;

  if (!(new = whine_malloc(size)))
    {
      errno = ENOMEM;
      return 0;
    }

  if (iov->iov_base)
    {
      memcpy(new, iov->iov_base, iov->iov_len);
      free(iov->iov_base);
    }

  iov->iov_base = new;
  iov->iov_len = size;

  return 1;
}

/**
 * @brief Format MAC address or byte array as colon-separated hex string
 *
 * @detailed Converts byte array (typically MAC address) to hex string format "01:23:45:67:89:ab".
 * Handles variable length including zero (displays "<null>"). Returns pointer to buff for
 * convenient use in printf-style calls.
 *
 * @param buff Output buffer for formatted string (must be ≥3*len bytes for "XX:" per byte + null)
 * @param mac Input byte array (MAC address or hex data)
 * @param len Length of mac array in bytes (0 for null)
 *
 * @return Pointer to buff (same as first parameter for chaining)
 *
 * @note Returns "<null>" if len==0
 * @warning Buffer must be large enough: at least 3*len bytes (2 hex + colon per byte + null)
 * @see prettyprint_addr() for IP addresses, used in DHCP logging
 *
 * EXAMPLE USAGE:
 * @code
 * char macbuf[3*6];
 * unsigned char mac[6] = {0x01,0x23,0x45,0x67,0x89,0xab};
 * my_syslog(LOG_INFO, "MAC: %s", print_mac(macbuf, mac, 6));
 * // Logs "MAC: 01:23:45:67:89:ab"
 * @endcode
 *
 * RFC COMPLIANCE: N/A (display formatting utility)
 *
 * SIDE EFFECTS: Writes to buff
 *
 * THREAD SAFETY: Thread-safe if different threads use different buff pointers
 */
char *print_mac(char *buff, unsigned char *mac, int len)
{
  char *p = buff;
  int i;
   
  if (len == 0)
    sprintf(p, "<null>");
  else
    for (i = 0; i < len; i++)
      p += sprintf(p, "%.2x%s", mac[i], (i == len - 1) ? "" : ":");
  
  return buff;
}

/**
 * @brief Determine if network send should be retried based on result code and errno
 *
 * @detailed Analyzes return value from sendto/sendmsg and errno to decide if operation should
 * be retried. Handles EAGAIN/EWOULDBLOCK with 1-second retry limit (1000 attempts × 10μs sleep)
 * to prevent hang on interface removal. Always retries EINTR. Sets errno=0 on success (rc != -1).
 *
 * @param rc Return code from sendto/sendmsg (-1 for error, ≥0 for success)
 *
 * @return 1 to retry send, 0 to stop (either success or unrecoverable error)
 * @retval 0 Success (rc != -1) or unrecoverable error - stop retrying (errno preserved or set to 0)
 * @retval 1 Transient error - retry send (EAGAIN/EWOULDBLOCK with backoff, or EINTR)
 *
 * @note Uses static retry counter - not thread-safe
 * @warning Linux kernels may return EAGAIN indefinitely when interface removed (workaround: 1s max retry)
 * @see read_write() for I/O retry wrapper, used in network sending functions
 *
 * EXAMPLE USAGE:
 * @code
 * ssize_t rc;
 * do {
 *     rc = sendto(fd, packet, len, 0, &dest, sizeof(dest));
 * } while (retry_send(rc));
 * if (rc == -1)  // Failed after retries
 *     handle_send_error();
 * @endcode
 *
 * RFC COMPLIANCE: N/A (error handling utility)
 *
 * SIDE EFFECTS:
 * - Increments static retries counter (reset on success)
 * - Sleeps 10μs on EAGAIN/EWOULDBLOCK
 * - Sets errno=0 on success
 *
 * THREAD SAFETY: NOT thread-safe due to static retries counter
 */
int retry_send(ssize_t rc)
{
  static int retries = 0;
  struct timespec waiter;
  
  if (rc != -1)
    {
      retries = 0;
      errno = 0;
      return 0;
    }
  
  /* Linux kernels can return EAGAIN in perpetuity when calling
     sendmsg() and the relevant interface has gone. Here we loop
     retrying in EAGAIN for 1 second max, to avoid this hanging 
     dnsmasq. */

  if (errno == EAGAIN || errno == EWOULDBLOCK)
     {
       waiter.tv_sec = 0;
       waiter.tv_nsec = 10000;
       nanosleep(&waiter, NULL);
       if (retries++ < 1000)
	 return 1;
     }
  
  retries = 0;
  
  if (errno == EINTR)
    return 1;
  
  return 0;
}

/**
 * @brief Reliable read or write handling partial transfers and interrupts
 *
 * @detailed Wrapper for read/write that loops until all 'size' bytes transferred or error occurs.
 * Automatically retries on EINTR, EAGAIN, ENOMEM, ENOBUFS using retry_send(). Returns 1 only
 * if all bytes successfully transferred, 0 on any error or EOF. Used for random seed I/O and
 * critical data transfers.
 *
 * @param fd File descriptor for read or write
 * @param packet Buffer for read/write data
 * @param size Number of bytes to transfer (must complete fully)
 * @param rw Direction: non-zero for read, zero for write
 *
 * @return 1 if all bytes transferred, 0 on error or premature EOF
 * @retval 0 Error occurred, EOF reached, or partial transfer (errno may be set)
 * @retval 1 All 'size' bytes successfully read or written
 *
 * @note Loops until complete or error - may block
 * @warning Returns 0 on EOF (n==0 from read) even if some bytes transferred
 * @see retry_send() for retry logic, rand_init() uses this for reading entropy
 *
 * EXAMPLE USAGE:
 * @code
 * int fd = open("/dev/urandom", O_RDONLY);
 * unsigned char entropy[32];
 * if (!read_write(fd, entropy, 32, 1))
 *     die("cannot read entropy");  // Failed to read all 32 bytes
 * @endcode
 *
 * RFC COMPLIANCE: N/A (I/O utility)
 *
 * SIDE EFFECTS:
 * - Blocks until all bytes transferred or error
 * - May call retry_send() which sleeps on EAGAIN
 * - Reads from or writes to file descriptor
 *
 * THREAD SAFETY: Thread-safe if different threads use different fds and buffers
 */
int read_write(int fd, unsigned char *packet, int size, int rw)
{
  ssize_t n, done;
  
  for (done = 0; done < size; done += n)
    {
      do { 
	if (rw)
	  n = read(fd, &packet[done], (size_t)(size - done));
	else
	  n = write(fd, &packet[done], (size_t)(size - done));
	
	if (n == 0)
	  return 0;
	
      } while (retry_send(n) || errno == ENOMEM || errno == ENOBUFS);

      if (errno != 0)
	return 0;
    }
     
  return 1;
}

/**
 * @brief Close all file descriptors except standard streams and specified spares
 *
 * @detailed Closes all open file descriptors from 0 to max_fd-1 except STDIN (0), STDOUT (1),
 * STDERR (2), and up to 3 spare fds. On Linux with /proc/self/fd, efficiently iterates only
 * open fds. Otherwise, iterates all possible fds (slower). Used during daemonization and
 * privilege drop to prevent fd leaks.
 *
 * @param max_fd Upper limit of file descriptors to check (typically sysconf(_SC_OPEN_MAX))
 * @param spare1 First file descriptor to preserve (or -1 to ignore)
 * @param spare2 Second file descriptor to preserve (or -1 to ignore)
 * @param spare3 Third file descriptor to preserve (or -1 to ignore)
 *
 * @return void
 *
 * @note Linux optimization: Uses /proc/self/fd to find open fds (much faster than iterating all)
 * @warning May close unexpected fds if max_fd set too high - use sysconf(_SC_OPEN_MAX)
 * @see Used in daemonize() and helper process setup
 *
 * EXAMPLE USAGE:
 * @code
 * long max = sysconf(_SC_OPEN_MAX);
 * int logfd = open("/var/log/dnsmasq.log", O_WRONLY);
 * close_fds(max, logfd, -1, -1);  // Close all except stdin/out/err and logfd
 * @endcode
 *
 * RFC COMPLIANCE: N/A (fd management utility)
 *
 * SIDE EFFECTS:
 * - Closes file descriptors
 * - Opens and reads /proc/self/fd directory (Linux only)
 *
 * THREAD SAFETY: NOT thread-safe - closes fds that may be used by other threads
 */
void close_fds(long max_fd, int spare1, int spare2, int spare3) 
{
  /* On Linux, use the /proc/ filesystem to find which files
     are actually open, rather than iterate over the whole space,
     for efficiency reasons. If this fails we drop back to the dumb code. */
#ifdef HAVE_LINUX_NETWORK 
  DIR *d;
  
  if ((d = opendir("/proc/self/fd")))
    {
      struct dirent *de;

      while ((de = readdir(d)))
	{
	  long fd;
	  char *e = NULL;
	  
	  errno = 0;
	  fd = strtol(de->d_name, &e, 10);
	  	  
      	  if (errno != 0 || !e || *e || fd == dirfd(d) ||
	      fd == STDOUT_FILENO || fd == STDERR_FILENO || fd == STDIN_FILENO ||
	      fd == spare1 || fd == spare2 || fd == spare3)
	    continue;
	  
	  close(fd);
	}
      
      closedir(d);
      return;
  }
#endif

  /* fallback, dumb code. */
  for (max_fd--; max_fd >= 0; max_fd--)
    if (max_fd != STDOUT_FILENO && max_fd != STDERR_FILENO && max_fd != STDIN_FILENO &&
	max_fd != spare1 && max_fd != spare2 && max_fd != spare3)
      close(max_fd);
}

/**
 * @brief Match a string against a wildcard pattern
 *
 * @detailed Compares a string value against a wildcard pattern where '*' matches any sequence
 * of characters. Returns 1 if the string matches the pattern, 0 otherwise. Stops immediately
 * when '*' is encountered (treating rest as match). Simple single-wildcard matching, not full
 * glob pattern support.
 *
 * @param wildcard Pattern string containing optional '*' wildcard character
 * @param match String to test against the wildcard pattern
 *
 * @return 1 if match successful, 0 if no match
 * @retval 1 String matches pattern (including '*' wildcard)
 * @retval 0 String does not match pattern
 *
 * @note Asterisk (*) matches any remaining characters - comparison stops at first '*'
 * @warning Simple wildcard only - not full regex or glob pattern matching
 * @see wildcard_matchn() for length-limited version
 *
 * EXAMPLE USAGE:
 * @code
 * if (wildcard_match("*.example.com", "www.example.com"))
 *     printf("Match!\n");  // Would match due to '*' at start
 * @endcode
 *
 * RFC COMPLIANCE: N/A (string matching utility)
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY: Thread-safe (no shared state, read-only parameters)
 */
int wildcard_match(const char* wildcard, const char* match)
{
  while (*wildcard && *match)
    {
      if (*wildcard == '*')
        return 1;

      if (*wildcard != *match)
        return 0; 

      ++wildcard;
      ++match;
    }

  return *wildcard == *match;
}

/**
 * @brief Match a string against a wildcard pattern with length limit
 *
 * @detailed Like wildcard_match() but compares at most num characters, similar to strncmp().
 * Returns 1 if the first num characters match the pattern, 0 otherwise. If num characters
 * are exhausted before mismatch or wildcard, returns 1. Useful for matching prefixes.
 *
 * @param wildcard Pattern string containing optional '*' wildcard character
 * @param match String to test against the wildcard pattern
 * @param num Maximum number of characters to compare
 *
 * @return 1 if match successful within num characters, 0 if no match
 * @retval 1 String matches pattern for first num chars (or wildcard encountered, or both ended)
 * @retval 0 String does not match pattern within first num chars
 *
 * @note Returns 1 if num==0 (zero-length comparison always matches)
 * @note Returns 1 if '*' encountered before num exhausted
 * @warning Simple wildcard only - not full regex or glob pattern matching
 * @see wildcard_match() for unlimited version, strncmp() for similar length-limited comparison
 *
 * EXAMPLE USAGE:
 * @code
 * if (wildcard_matchn("prefix*", "prefix-suffix", 6))
 *     printf("Prefix matches!\n");  // Matches "prefix"
 * @endcode
 *
 * RFC COMPLIANCE: N/A (string matching utility)
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY: Thread-safe (no shared state, read-only parameters)
 */
int wildcard_matchn(const char* wildcard, const char* match, int num)
{
  while (*wildcard && *match && num)
    {
      if (*wildcard == '*')
        return 1;

      if (*wildcard != *match)
        return 0; 

      ++wildcard;
      ++match;
      --num;
    }

  return (!num) || (*wildcard == *match);
}

#ifdef HAVE_LINUX_NETWORK
/**
 * @brief Get Linux kernel version as integer for feature detection
 *
 * @detailed Parses the kernel version from uname() and returns it as a single integer
 * in the format: (major * 256 + minor) * 256 + patch. For example, kernel 5.4.1 returns
 * (5*256+4)*256+1 = 328705. Used to detect kernel capabilities and enable version-specific
 * features like netlink extensions or newer socket options.
 *
 * @return Kernel version as integer (major*65536 + minor*256 + patch)
 * @retval >0 Kernel version encoded as integer
 *
 * @note Linux-only function (HAVE_LINUX_NETWORK)
 * @warning Dies with EC_MISC if uname() fails
 * @see Used in netlink.c and network.c for kernel feature detection
 *
 * EXAMPLE USAGE:
 * @code
 * int kver = kernel_version();
 * if (kver >= (2 * 256 + 6) * 256)  // Check for kernel 2.6.0+
 *     use_new_netlink_features();
 * @endcode
 *
 * RFC COMPLIANCE: N/A (Linux kernel version detection)
 *
 * SIDE EFFECTS:
 * - Calls uname() to query kernel version
 * - Calls die() if uname() fails
 * - Modifies static buffers in strtok()
 *
 * THREAD SAFETY: NOT thread-safe due to strtok() use
 */
int kernel_version(void)
{
  struct utsname utsname;
  int version;
  char *split;
  
  if (uname(&utsname) < 0)
    die(_("failed to find kernel version: %s"), NULL, EC_MISC);
  
  split = strtok(utsname.release, ".");
  version = (split ? atoi(split) : 0);
  split = strtok(NULL, ".");
  version = version * 256 + (split ? atoi(split) : 0);
  split = strtok(NULL, ".");
  return version * 256 + (split ? atoi(split) : 0);
}
#endif
