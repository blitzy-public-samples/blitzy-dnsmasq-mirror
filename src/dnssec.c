/* dnssec.c is Copyright (c) 2012 Giovanni Bajo <rasky@develer.com>
           and Copyright (c) 2012-2020 Simon Kelley

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
 * @file dnssec.c
 * @brief DNSSEC validation implementation per RFCs 4033/4034/4035
 *
 * DETAILED PURPOSE:
 * This file implements complete DNSSEC validation for DNS responses, providing cryptographic
 * verification of DNS data integrity and authenticity. It handles the full DNSSEC validation
 * pipeline including DNSKEY retrieval and verification, DS (Delegation Signer) chain validation
 * from root to target zone, RRSIG (Resource Record Signature) verification over answer RRsets,
 * NSEC/NSEC3 denial-of-existence proofs for negative answers, DNS name canonicalization for
 * signature verification, timestamp checking (inception/expiration times), and trust anchor
 * management. The implementation validates DNS responses against the chain of trust established
 * from configured trust anchors (typically the root zone KSK) down to the queried domain.
 *
 * The validation process produces one of four states: secure (valid signatures with complete
 * chain of trust), insecure (unsigned delegation or zone), bogus (invalid or missing signatures),
 * or indeterminate (unable to validate due to missing data or errors). DNSSEC validation is
 * triggered when the DO (DNSSEC OK) bit is set in queries and HAVE_DNSSEC is compiled in.
 *
 * KEY RESPONSIBILITIES:
 * - dnssec_validate_by_ds() - Validates DNSKEY RRset against parent zone DS records, establishing
 *   trust for a zone's public keys (lines 762-991)
 * - dnssec_validate_reply() - Main validation entry point, validates all RRsets in answer section
 *   and handles CNAME chains, wildcard expansion, and negative answers (lines 1860-2118)
 * - dnssec_validate_ds() - Validates DS records by checking DNSKEY signatures in child zone,
 *   used for building chain of trust (lines 993-1128)
 * - validate_rrset() - Core signature verification, checks RRSIG over RRset using DNSKEY,
 *   performs cryptographic verification via crypto.c (lines 520-760)
 * - explore_rrset() - Processes NSEC/NSEC3 records for denial-of-existence proofs, validates
 *   that queried name/type genuinely does not exist (lines 397-518)
 * - prove_non_existence() - Coordinates NSEC/NSEC3 proof validation for negative answers and
 *   wildcard responses (lines 1636-1766)
 * - setup_timestamp() - Initializes timestamp file for time validation on systems with
 *   unreliable RTC (embedded systems) (lines 143-186)
 *
 * DEPENDENCIES:
 * - #include "dnsmasq.h" - Primary header with struct definitions (daemon, dns_header, blockdata)
 * - crypto.c - Cryptographic primitive wrappers (verify_sha256(), verify_ecdsa(), etc.)
 * - rfc1035.c - DNS packet parsing (extract_name()) and DNS protocol constants
 * - blockdata.c - Variable-length data storage for DNSSEC records
 * - Calls: verify_sha256(), verify_sha256(), verify_ecdsa(), verify_ecdsa384(), algo_digest_name()
 * - Called by: forward.c forward_query(), reply_query() when DNSSEC validation enabled
 *
 * DATA STRUCTURES:
 * - struct rdata_state (lines 227-232) - Iterator state for canonicalizing RRset data during
 *   signature verification, tracks position in RDATA and descriptor
 * - struct dns_header (dnsmasq.h) - DNS packet header used throughout validation
 * - struct blockdata (dnsmasq.h) - Storage for DNSSEC record data (RRSIGs, DNSKEYs, DS records)
 * - timestamp_time (line 141) - Static timestamp for systems without RTC, initialized from
 *   persistent file
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC (line 20) - MANDATORY: Entire file compiled only if defined, enables all DNSSEC
 *   functionality
 * - Requires: libnettle and libhogweed for cryptographic operations (linked via crypto.c)
 * - Requires: DNSSEC resource record type support (DNSKEY type 48, RRSIG type 46, DS type 43,
 *   NSEC type 47, NSEC3 type 50)
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. DNSSEC validation occurs synchronously within the
 * DNS query handling path. Uses cached DNSSEC records (DNSKEYs, DS records) to minimize
 * validation latency. No multi-threading; validation state maintained in stack-allocated
 * structures during query processing. Timestamp file (setup_timestamp()) requires atomic file
 * operations via O_EXCL flag. Validation results cached in DNS cache alongside answer data.
 *
 * @see docs/DNSSEC.md for complete DNSSEC validation algorithm and RFC compliance
 * @see crypto.c for cryptographic primitive implementations
 * @see docs/ARCHITECTURE.md for integration with DNS forwarding pipeline
 *
 * @copyright Copyright (c) 2012 Giovanni Bajo <rasky@develer.com>
 *            Copyright (c) 2012-2020 Simon Kelley
 * @license GNU General Public License v2 or later
 */

#include "dnsmasq.h"

#ifdef HAVE_DNSSEC

#define SERIAL_UNDEF  -100
#define SERIAL_EQ        0
#define SERIAL_LT       -1
#define SERIAL_GT        1

/**
 * @brief Convert DNS name from presentation format to wire format in place
 *
 * @detailed
 * Converts a DNS name from human-readable presentation format (dot-separated labels) to DNS
 * wire format (length-prefixed labels) in place. Also performs case normalization by mapping
 * uppercase to lowercase characters as required for DNSSEC canonical form per RFC 4034 Section 6.2.
 * Handles escaped special characters (NAME_ESCAPE) which represent '.' and NUL within labels.
 * Using extract_name() followed by to_wire() removes DNS name compression and generates canonical
 * form suitable for signature verification. The operation is nearly reversible with from_wire()
 * except that uppercase remains mapped to lowercase.
 *
 * @param name DNS name string in presentation format, modified in place to wire format.
 *             Must be NUL-terminated. Buffer must accommodate length-prefix bytes.
 *             Labels separated by dots, special characters escaped with NAME_ESCAPE.
 *             Maximum length 2049 bytes to handle fully escaped names (spec is 1024 bytes).
 *
 * @return Length of wire-format name in bytes including final zero-length label.
 *         Returns distance from start to end of wire-format name.
 *
 * @note Modifies input buffer in place. Original presentation format is destroyed.
 * @note Both NUL (\\000) and '.' are allowed within labels when escaped with NAME_ESCAPE.
 * @note Buffer sizing: 2049 bytes accommodates worst case where all characters require escaping
 *       in presentation format (theoretical maximum is 2x spec of 1024).
 *
 * @warning Input name must not be DNS-compressed (no compression pointers). Use extract_name()
 *          first if name is from wire format packet.
 *
 * @see from_wire() for reverse conversion (wire format to presentation format)
 * @see RFC 4034 Section 6.2 for canonical form requirements
 * @see RFC 1035 Section 3.1 for DNS name format specification
 *
 * EXAMPLE USAGE:
 * @code
 * char namebuf[2049];
 * strcpy(namebuf, "www.example.com");
 * int wirelen = to_wire(namebuf);
 * // namebuf now contains: \x03www\x07example\x03com\x00
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4034 Section 6.2 canonical form (case normalization) and
 * RFC 1035 Section 3.1 wire format with length-prefixed labels.
 *
 * SIDE EFFECTS: Modifies name buffer in place, destroys presentation format.
 *
 * THREAD SAFETY: Reentrant if separate name buffers used. No global state.
 */
static int to_wire(char *name)
{
  unsigned char *l, *p, *q, term;
  int len;

  for (l = (unsigned char*)name; *l != 0; l = p)
    {
      for (p = l; *p != '.' && *p != 0; p++)
	if (*p >= 'A' && *p <= 'Z')
	  *p = *p - 'A' + 'a';
	else if (*p == NAME_ESCAPE)
	  {
	    for (q = p; *q; q++)
	      *q = *(q+1);
	    (*p)--;
	  }
      term = *p;
      
      if ((len = p - l) != 0)
	memmove(l+1, l, len);
      *l = len;
      
      p++;
      
      if (term == 0)
	*p = 0;
    }
  
  return l + 1 - (unsigned char *)name;
}

/**
 * @brief Convert DNS name from wire format to presentation format in place
 *
 * @detailed
 * Converts a DNS name from wire format (length-prefixed labels) back to human-readable
 * presentation format (dot-separated labels) in place. Escapes special characters (NUL, dot,
 * NAME_ESCAPE) using NAME_ESCAPE prefix as required for safe representation. This is the inverse
 * operation of to_wire(), used for displaying DNS names after validation. Note that uppercase
 * characters are NOT restored if they were previously normalized by to_wire().
 *
 * @param name DNS name string in wire format, modified in place to presentation format.
 *             Must start with length-prefixed labels and end with zero-length label.
 *             No DNS compression pointers allowed. Buffer must accommodate escaped characters
 *             (up to 2x expansion for fully escaped names).
 *
 * @return void (no return value)
 *
 * @note Modifies input buffer in place. Original wire format is destroyed.
 * @note Does not restore uppercase characters if they were previously normalized.
 * @note Special characters (NUL, dot, NAME_ESCAPE) are escaped with NAME_ESCAPE prefix.
 *
 * @warning Input name must not contain DNS compression pointers. Use extract_name() to
 *          decompress first if name is from compressed packet.
 * @warning Buffer must be large enough to accommodate escaped output (potentially 2x input).
 *
 * @see to_wire() for conversion to wire format
 * @see extract_name() in rfc1035.c for decompressing DNS names from packets
 *
 * EXAMPLE USAGE:
 * @code
 * char namebuf[2049] = "\x03www\x07example\x03com\x00";  // wire format
 * from_wire(namebuf);
 * // namebuf now contains: "www.example.com" (presentation format)
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 1035 Section 3.1 wire format parsing and RFC 4034 Section 6.2
 * canonical form handling.
 *
 * SIDE EFFECTS: Modifies name buffer in place, destroys wire format.
 *
 * THREAD SAFETY: Reentrant if separate name buffers used. No global state.
 */
static void from_wire(char *name)
{
  unsigned char *l, *p, *last;
  int len;
  
  for (last = (unsigned char *)name; *last != 0; last += *last+1);
  
  for (l = (unsigned char *)name; *l != 0; l += len+1)
    {
      len = *l;
      memmove(l, l+1, len);
      for (p = l; p < l + len; p++)
	if (*p == '.' || *p == 0 || *p == NAME_ESCAPE)
	  {
	    memmove(p+1, p, 1 + last - p);
	    len++;
	    *p++ = NAME_ESCAPE; 
	    (*p)++;
	  }
	
      l[len] = '.';
    }

  if ((char *)l != name)
    *(l-1) = 0;
}

/**
 * @brief Count number of labels in DNS name in presentation format
 *
 * @detailed
 * Counts the number of labels in a DNS name by counting dots as label separators. A label is
 * a component of a domain name between dots (e.g., "www.example.com" has 3 labels: www, example,
 * com). Empty first label (name starting with '.') is not counted, supporting relative names.
 * Used in DNSSEC validation to determine zone boundaries and wildcard matching depth per
 * RFC 4035 Section 5.3.
 *
 * @param name DNS name string in presentation format (dot-separated labels), NUL-terminated.
 *             Expected format: "label1.label2.label3" or ".label1.label2" for relative names.
 *             Empty string ("") is valid and returns 0.
 *
 * @return Number of labels in the name. Returns 0 for empty string. Returns i+1 where i is
 *         the count of dots, unless name starts with '.' in which case returns i (ignoring
 *         empty first label).
 *
 * @note Empty first label (name starting with '.') is intentionally not counted.
 * @note This function operates on presentation format, not wire format.
 *
 * EXAMPLE USAGE:
 * @code
 * int labels1 = count_labels("www.example.com");  // Returns 3
 * int labels2 = count_labels(".example.com");     // Returns 2 (empty first label ignored)
 * int labels3 = count_labels("");                 // Returns 0
 * @endcode
 *
 * RFC COMPLIANCE: Supports RFC 4035 Section 5.3 label counting for wildcard matching and
 * zone cut determination.
 *
 * SIDE EFFECTS: None (read-only operation).
 *
 * THREAD SAFETY: Reentrant, read-only access to input.
 */
static int count_labels(char *name)
{
  int i;
  char *p;
  
  if (*name == 0)
    return 0;

  for (p = name, i = 0; *p; p++)
    if (*p == '.')
      i++;

  /* Don't count empty first label. */
  return *name == '.' ? i : i+1;
}

/**
 * @brief Compare 32-bit serial numbers using RFC 1982 modular arithmetic
 *
 * @detailed
 * Implements RFC 1982 serial number arithmetic for comparing 32-bit values that wrap around at
 * 2^32. This is critical for DNSSEC signature timestamp comparison (inception/expiration times)
 * which use 32-bit UNIX timestamps that will wrap in year 2106. The algorithm defines s1 < s2
 * if (s1 < s2 and s2 - s1 < 2^31) or (s1 > s2 and s1 - s2 > 2^31), handling wraparound correctly.
 *
 * @param s1 First 32-bit serial number to compare
 * @param s2 Second 32-bit serial number to compare
 *
 * @return SERIAL_EQ (0) if s1 == s2
 * @retval SERIAL_LT (-1) if s1 is less than s2 in modular arithmetic
 * @retval SERIAL_GT (1) if s1 is greater than s2 in modular arithmetic
 * @retval SERIAL_UNDEF (-100) if comparison is undefined (difference exactly 2^31)
 *
 * @note SERIAL_UNDEF is returned when values differ by exactly 2^31, which is ambiguous in
 *       modular arithmetic (could be +2^31 or -2^31).
 * @note Used for DNSSEC RRSIG inception/expiration timestamp comparison in validate_rrset().
 *
 * @see validate_rrset() where this is used for timestamp validation
 * @see RFC 1982 for serial number arithmetic specification
 *
 * EXAMPLE USAGE:
 * @code
 * u32 sig_inception = 1609459200;  // 2021-01-01
 * u32 current_time = 1640995200;   // 2022-01-01
 * if (serial_compare_32(sig_inception, current_time) == SERIAL_LT) {
 *     // Signature inception is before current time (valid)
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 1982 serial number arithmetic for 32-bit values. Used for
 * RFC 4034 Section 3.1.5 RRSIG signature validity period checking.
 *
 * SIDE EFFECTS: None (pure function).
 *
 * THREAD SAFETY: Reentrant, no global state.
 */
static int serial_compare_32(u32 s1, u32 s2)
{
  if (s1 == s2)
    return SERIAL_EQ;

  if ((s1 < s2 && (s2 - s1) < (1UL<<31)) ||
      (s1 > s2 && (s1 - s2) > (1UL<<31)))
    return SERIAL_LT;
  if ((s1 < s2 && (s2 - s1) > (1UL<<31)) ||
      (s1 > s2 && (s1 - s2) < (1UL<<31)))
    return SERIAL_GT;
  return SERIAL_UNDEF;
}

/**
 * @brief Initialize DNSSEC timestamp validation for systems without reliable RTC
 *
 * @detailed
 * Initializes timestamp validation mechanism for embedded systems with broken or absent real-time
 * clocks (HAVE_BROKEN_RTC). Creates or validates persistent timestamp file whose mtime tracks
 * when system time became reliable. If file doesn't exist, creates it with mtime set to
 * 2015-01-01 (epoch 1420070400). If file exists and mtime is in future, DNSSEC validation
 * defers timestamp checking until system time catches up. Once system time exceeds file mtime,
 * updates file and enables full DNSSEC signature timestamp validation. This prevents false
 * validation failures when system boots with incorrect time (common on embedded devices).
 *
 * @param void (no parameters, uses daemon->timestamp_file global configuration)
 *
 * @return Status code indicating timestamp file state and time validity
 * @retval -1 Cannot create timestamp file (permission error or filesystem issue)
 * @retval 0 Not using timestamp file, OR timestamp exists and system time is already past it
 *            (normal operation, timestamp checking enabled)
 * @retval 1 Timestamp file exists but system time is still before its mtime (time not yet valid,
 *            defer timestamp checking)
 *
 * @note Uses daemon->timestamp_file path from configuration (NULL if not configured).
 * @note Sets daemon->back_to_the_future flag based on time validity.
 * @note File created with O_EXCL to prevent race conditions (see dnsmasq.c pidfile comment).
 * @note Default timestamp epoch (1420070400) is 2015-01-01 00:00:00 UTC.
 *
 * @warning Requires writable filesystem at daemon->timestamp_file path.
 * @warning File mtime update (utimes()) failure logged but not fatal.
 *
 * @see is_check_date() which uses timestamp_time for validation decisions
 * @see dnssec_validate_reply() which honors daemon->dnssec_no_time_check flag
 *
 * EXAMPLE USAGE:
 * @code
 * daemon->timestamp_file = "/var/lib/dnsmasq/dnsmasq.time";
 * int status = setup_timestamp();
 * if (status == -1) {
 *     my_syslog(LOG_ERR, "Failed to create timestamp file");
 * } else if (status == 1) {
 *     my_syslog(LOG_INFO, "Waiting for system time to become valid");
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Supports RFC 4034 Section 3.1.5 RRSIG signature validity period checking on
 * systems without reliable RTC. Allows deferral of timestamp validation until time is correct.
 *
 * SIDE EFFECTS:
 * - Creates timestamp file at daemon->timestamp_file if it doesn't exist
 * - Updates file mtime if system time is valid
 * - Sets static timestamp_time variable
 * - Sets daemon->back_to_the_future flag
 * - Logs to syslog on file operation errors
 *
 * THREAD SAFETY: Called once at startup before event loop. Not reentrant due to static
 * timestamp_time variable.
 */

static time_t timestamp_time;

int setup_timestamp(void)
{
  struct stat statbuf;
  
  daemon->back_to_the_future = 0;
  
  if (!daemon->timestamp_file)
    return 0;
  
  if (stat(daemon->timestamp_file, &statbuf) != -1)
    {
      timestamp_time = statbuf.st_mtime;
    check_and_exit:
      if (difftime(timestamp_time, time(0)) <=  0)
	{
	  /* time already OK, update timestamp, and do key checking from the start. */
	  if (utimes(daemon->timestamp_file, NULL) == -1)
	    my_syslog(LOG_ERR, _("failed to update mtime on %s: %s"), daemon->timestamp_file, strerror(errno));
	  daemon->back_to_the_future = 1;
	  return 0;
	}
      return 1;
    }
  
  if (errno == ENOENT)
    {
      /* NB. for explanation of O_EXCL flag, see comment on pidfile in dnsmasq.c */ 
      int fd = open(daemon->timestamp_file, O_WRONLY | O_CREAT | O_NONBLOCK | O_EXCL, 0666);
      if (fd != -1)
	{
	  struct timeval tv[2];

	  close(fd);
	  
	  timestamp_time = 1420070400; /* 1-1-2015 */
	  tv[0].tv_sec = tv[1].tv_sec = timestamp_time;
	  tv[0].tv_usec = tv[1].tv_usec = 0;
	  if (utimes(daemon->timestamp_file, tv) == 0)
	    goto check_and_exit;
	}
    }

  return -1;
}

/**
 * @brief Determine if DNSSEC signature timestamp checking should be performed
 *
 * @detailed
 * Determines whether current time is reliable enough to perform DNSSEC signature validity period
 * checks (inception/expiration timestamps). On systems with broken RTC (embedded devices),
 * defers timestamp checking until system time becomes valid as indicated by timestamp file mtime.
 * Once system time exceeds timestamp file mtime, updates file, logs time validity, triggers cache
 * purge (EVENT_RELOAD), and enables timestamp checking. Supports gradual transition from
 * time-unknown to time-valid state without disrupting DNSSEC validation.
 *
 * @param curtime Current time as UNIX timestamp (seconds since epoch). Typically time(NULL).
 *                Used to compare against persistent timestamp_time from timestamp file.
 *
 * @return Boolean indicating whether signature timestamps should be checked
 * @retval 1 (true) Time is considered valid, check RRSIG inception/expiration timestamps
 * @retval 0 (false) Time is not yet valid, skip timestamp checks (accept all non-expired sigs)
 *
 * @note Returns 1 if daemon->timestamp_file is NULL (normal systems with RTC).
 * @note Returns daemon->back_to_the_future if timestamp file is configured.
 * @note Returns !daemon->dnssec_no_time_check as fallback for non-timestamp systems.
 * @note One-time transition: daemon->back_to_the_future changes from 0 to 1 when time becomes
 *       valid.
 *
 * @warning File mtime update failure (utimes()) is logged but does not prevent time validation.
 * @warning Triggers EVENT_RELOAD (cache purge) when transitioning from invalid to valid time,
 *          removing potentially incorrectly validated entries.
 *
 * @see setup_timestamp() which initializes timestamp_time and timestamp file
 * @see validate_rrset() which calls is_check_date() before checking RRSIG timestamps
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned long now = time(NULL);
 * if (is_check_date(now)) {
 *     // Check RRSIG inception and expiration timestamps
 *     if (sig_inception > now || sig_expiration < now) {
 *         return STAT_BOGUS;  // Signature outside validity period
 *     }
 * }
 * // Else skip timestamp checks, validate signature cryptographically only
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4034 Section 3.1.5 RRSIG signature validity period enforcement
 * with accommodation for systems without reliable RTC.
 *
 * SIDE EFFECTS:
 * - Updates timestamp file mtime via utimes() when transitioning to valid time
 * - Sets daemon->back_to_the_future = 1 on transition
 * - Sets daemon->dnssec_no_time_check = 0 on transition
 * - Triggers EVENT_RELOAD (cache purge) via queue_event() on transition
 * - Logs "system time considered valid" message to syslog on transition
 *
 * THREAD SAFETY: Called within query processing path. Uses static timestamp_time (set at startup).
 * Transition logic (daemon->back_to_the_future update) is not atomic but occurs only once.
 */
static int is_check_date(unsigned long curtime)
{
  /* Checking timestamps may be temporarily disabled */
    
  /* If the current time if _before_ the timestamp
     on our persistent timestamp file, then assume the
     time if not yet correct, and don't check the
     key timestamps. As soon as the current time is
     later then the timestamp, update the timestamp
     and start checking keys */
  if (daemon->timestamp_file)
    {
      if (daemon->back_to_the_future == 0 && difftime(timestamp_time, curtime) <= 0)
	{
	  if (utimes(daemon->timestamp_file, NULL) != 0)
	    my_syslog(LOG_ERR, _("failed to update mtime on %s: %s"), daemon->timestamp_file, strerror(errno));
	  
	  my_syslog(LOG_INFO, _("system time considered valid, now checking DNSSEC signature timestamps."));
	  daemon->back_to_the_future = 1;
	  daemon->dnssec_no_time_check = 0;
	  queue_event(EVENT_RELOAD); /* purge cache */
	} 

      return daemon->back_to_the_future;
    }
  else
    return !daemon->dnssec_no_time_check;
}

/**
 * @brief Iterator to retrieve canonicalized RDATA bytes for DNSSEC signature verification
 *
 * @detailed
 * Iterates through RDATA (resource record data) one byte at a time, performing canonicalization
 * as required by RFC 4034 Section 6.2 for DNSSEC signature verification. Handles domain names
 * within RDATA by extracting and converting them to canonical wire format (lowercase, uncompressed)
 * using to_wire(). Uses RR type descriptor (state->desc) to identify which fields are domain names
 * vs raw data. Iterator state machine allows incremental byte-by-byte access suitable for feeding
 * to hash/signature algorithms. Descriptor value 0 indicates domain name field, positive values
 * indicate raw byte count, (u16)-1 indicates "all remaining bytes".
 *
 * @param header DNS packet header for extracting compressed names via extract_name()
 * @param plen Packet length in bytes for bounds checking during name extraction
 * @param state Iterator state structure tracking position and canonicalization progress.
 *              MUST be initialized before first call:
 *              - state->ip = start of RDATA
 *              - state->end = end of RDATA (one past last byte)
 *              - state->op = NULL
 *              - state->desc = pointer to RR type descriptor array
 *              - state->buff = buffer of size MAXDNAME * 2 for name canonicalization
 *
 * @return Iterator status
 * @retval 1 More data available. state->op points to next byte, state->c contains bytes remaining
 *           in current chunk. Call again to continue iteration.
 * @retval 0 End of RDATA reached. No more data available. Iteration complete.
 *
 * @note RR type descriptor format: array of u16 values terminated by (u16)-1. Value 0 = domain
 *       name (canonicalize), positive value N = N bytes of raw data, (u16)-1 = all remaining bytes.
 * @note Domain names are extracted from packet (handling compression), then converted to canonical
 *       wire format via to_wire() for signature verification.
 * @note State structure must remain valid across all calls for single RDATA iteration.
 * @note Advances state->desc pointer as descriptor entries are consumed.
 *
 * @warning State must be properly initialized before first call. Uninitialized state causes
 *          undefined behavior.
 * @warning extract_name() failure (compressed name extraction error) causes silent skip to next
 *          descriptor entry. Validation will likely fail due to incomplete canonicalization.
 *
 * @see to_wire() for domain name canonicalization
 * @see extract_name() in rfc1035.c for decompressing DNS names from packets
 * @see sort_rrset() and validate_rrset() which use get_rdata() for signature verification
 * @see RFC 4034 Section 6.2 for canonical RR form requirements
 *
 * EXAMPLE USAGE:
 * @code
 * struct rdata_state state;
 * char buff[MAXDNAME * 2];
 * u16 mx_desc[] = {2, 0, (u16)-1};  // MX: 2 bytes preference, domain name, end
 * state.ip = rdata_start;
 * state.end = rdata_end;
 * state.op = NULL;
 * state.desc = mx_desc;
 * state.buff = buff;
 * while (get_rdata(header, plen, &state)) {
 *     process_byte(*state.op);  // Feed to hash/signature algorithm
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4034 Section 6.2 canonical RR form for RRSIG signature
 * verification. Handles domain name canonicalization per RFC 4034 Section 6.2.
 *
 * SIDE EFFECTS:
 * - Advances state->ip through RDATA
 * - Advances state->desc through descriptor array
 * - Modifies state->buff during domain name canonicalization
 * - Updates state->op and state->c on each call
 *
 * THREAD SAFETY: Reentrant if separate state structures used. No global state.
 */
struct rdata_state {
  u16 *desc;
  size_t c;
  unsigned char *end, *ip, *op;
  char *buff;
};

static int get_rdata(struct dns_header *header, size_t plen, struct rdata_state *state)
{
  int d;
  
  if (state->op && state->c != 1)
    {
      state->op++;
      state->c--;
      return 1;
    }

  while (1)
    {
      d = *(state->desc);
      
      if (d == (u16)-1)
	{
	  /* all the bytes to the end. */
	  if ((state->c = state->end - state->ip) != 0)
	    {
	      state->op = state->ip;
	      state->ip = state->end;;
	    }
	  else
	    return 0;
	}
      else
	{
	  state->desc++;
	  
	  if (d == (u16)0)
	    {
	      /* domain-name, canonicalise */
	      int len;
	      
	      if (!extract_name(header, plen, &state->ip, state->buff, 1, 0) ||
		  (len = to_wire(state->buff)) == 0)
		continue;
	      
	      state->c = len;
	      state->op = (unsigned char *)state->buff;
	    }
	  else
	    {
	      /* plain data preceding a domain-name, don't run off the end of the data */
	      if ((state->end - state->ip) < d)
		d = state->end - state->ip;
	      
	      if (d == 0)
		continue;
		  
	      state->op = state->ip;
	      state->c = d;
	      state->ip += d;
	    }
	}
      
      return 1;
    }
}

/**
 * @brief Sort RRset into canonical order and remove duplicates for DNSSEC verification
 *
 * @detailed
 * Sorts RRset (Resource Record set) into canonical order as required by RFC 4034 Section 6.3 for
 * DNSSEC signature verification. Uses bubble sort to order RRs by comparing canonicalized RDATA
 * byte-by-byte. For RR types with domain names in RDATA, performs full canonicalization via
 * get_rdata(). For RR types with no domain names (rr_desc == (u16)-1), uses direct memcmp for
 * efficiency. Removes exact duplicate RRs per RFC 4034 Section 6.3 paragraph 3. Canonical order
 * is lexicographic comparison of canonicalized RDATA. Sorted order is required for consistent
 * signature generation and verification across different DNS implementations.
 *
 * @param header DNS packet header for name extraction during canonicalization
 * @param plen Packet length in bytes for bounds checking
 * @param rr_desc RR type descriptor array defining RDATA structure. Value 0 = domain name,
 *                positive N = N bytes raw data, (u16)-1 = all remaining bytes (no names).
 * @param rrsetidx Number of RRs in rrset array (input count, may be reduced by duplicate removal)
 * @param rrset Array of pointers to RRs in packet, modified in place for sorting. Each pointer
 *              points to owner name start of an RR. Array size must accommodate rrsetidx entries.
 * @param buff1 Temporary buffer of size MAXDNAME * 2 for first RR canonicalization
 * @param buff2 Temporary buffer of size MAXDNAME * 2 for second RR canonicalization
 *
 * @return Number of RRs remaining after duplicate removal. May be less than rrsetidx input if
 *         exact duplicates were found and removed. Returns rrsetidx on short packet error.
 *
 * @note Bubble sort algorithm used (O(n^2) worst case). Acceptable for typical RRset sizes (< 10).
 * @note Duplicate removal per RFC 4034 Section 6.3: "If an RRset contains RRs with different RDATA,
 *       but the same canonical form, only one RR is used for signature verification."
 * @note For optimization, RR types with no domain names in RDATA use direct memcmp instead of
 *       full canonicalization.
 * @note Modifies rrset array in place, reordering pointers. Original packet data unchanged.
 *
 * @warning Assumes all RRs in rrset are valid and bounds-checked prior to call. Short packet
 *          detection (CHECK_LEN failure) aborts sort and returns current rrsetidx.
 * @warning Requires buff1 and buff2 to be at least MAXDNAME * 2 bytes for name canonicalization.
 *
 * @see get_rdata() for canonicalized RDATA iteration
 * @see validate_rrset() which calls sort_rrset() before signature verification
 * @see RFC 4034 Section 6.3 for canonical RRset form and duplicate handling
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *rrset[10];
 * char buff1[MAXDNAME * 2], buff2[MAXDNAME * 2];
 * u16 a_desc[] = {(u16)-1};  // A record: 4 bytes raw data, no names
 * int count = 5;  // 5 A records in rrset
 * int final_count = sort_rrset(header, plen, a_desc, count, rrset, buff1, buff2);
 * // rrset now sorted, duplicates removed, final_count <= count
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4034 Section 6.3 canonical RRset form and ordering. Removes
 * duplicate RRs as required by RFC 4034 Section 6.3 for signature verification.
 *
 * SIDE EFFECTS:
 * - Reorders rrset array pointers in place
 * - Removes duplicate RR pointers from rrset (reduces rrsetidx)
 * - Modifies buff1 and buff2 during canonicalization comparisons
 *
 * THREAD SAFETY: Reentrant if separate rrset/buffer arrays used. No global state accessed.
 */

static int sort_rrset(struct dns_header *header, size_t plen, u16 *rr_desc, int rrsetidx, 
		      unsigned char **rrset, char *buff1, char *buff2)
{
  int swap, i, j;
  
  do
    {
      for (swap = 0, i = 0; i < rrsetidx-1; i++)
	{
	  int rdlen1, rdlen2;
	  struct rdata_state state1, state2;
	  
	  /* Note that these have been determined to be OK previously,
	     so we don't need to check for NULL return here. */
	  state1.ip = skip_name(rrset[i], header, plen, 10);
	  state2.ip = skip_name(rrset[i+1], header, plen, 10);
	  state1.op = state2.op = NULL;
	  state1.buff = buff1;
	  state2.buff = buff2;
	  state1.desc = state2.desc = rr_desc;
	  
	  state1.ip += 8; /* skip class, type, ttl */
	  GETSHORT(rdlen1, state1.ip);
	  if (!CHECK_LEN(header, state1.ip, plen, rdlen1))
	    return rrsetidx; /* short packet */
	  state1.end = state1.ip + rdlen1;
	  
	  state2.ip += 8; /* skip class, type, ttl */
	  GETSHORT(rdlen2, state2.ip);
	  if (!CHECK_LEN(header, state2.ip, plen, rdlen2))
	    return rrsetidx; /* short packet */
	  state2.end = state2.ip + rdlen2; 

	  /* If the RR has no names in it then canonicalisation
	     is the identity function and we can compare
	     the RRs directly. If not we compare the 
	     canonicalised RRs one byte at a time. */
	  if (*rr_desc == (u16)-1)	  
	    {
	      int rdmin = rdlen1 > rdlen2 ? rdlen2 : rdlen1;
	      int cmp = memcmp(state1.ip, state2.ip, rdmin);
	      
	      if (cmp > 0 || (cmp == 0 && rdlen1 > rdmin))
		{
		  unsigned char *tmp = rrset[i+1];
		  rrset[i+1] = rrset[i];
		  rrset[i] = tmp;
		  swap = 1;
		}
	      else if (cmp == 0 && (rdlen1 == rdlen2))
		{
		  /* Two RRs are equal, remove one copy. RFC 4034, para 6.3 */
		  for (j = i+1; j < rrsetidx-1; j++)
		    rrset[j] = rrset[j+1];
		  rrsetidx--;
		  i--;
		}
	    }
	  else
	    /* Comparing canonicalised RRs, byte-at-a-time. */
	    while (1)
	      {
		int ok1, ok2;
		
		ok1 = get_rdata(header, plen, &state1);
		ok2 = get_rdata(header, plen, &state2);
		
		if (!ok1 && !ok2)
		  {
		    /* Two RRs are equal, remove one copy. RFC 4034, para 6.3 */
		    for (j = i+1; j < rrsetidx-1; j++)
		      rrset[j] = rrset[j+1];
		    rrsetidx--;
		    i--;
		    break;
		  }
		else if (ok1 && (!ok2 || *state1.op > *state2.op)) 
		  {
		    unsigned char *tmp = rrset[i+1];
		    rrset[i+1] = rrset[i];
		    rrset[i] = tmp;
		    swap = 1;
		    break;
		  }
		else if (ok2 && (!ok1 || *state2.op > *state1.op))
		  break;
		
		/* arrive here when bytes are equal, go round the loop again
		   and compare the next ones. */
	      }
	}
    } while (swap);

  return rrsetidx;
}

static unsigned char **rrset = NULL, **sigs = NULL;

/**
 * @brief Extract RRset and corresponding RRSIG records from DNS packet for validation
 *
 * @detailed
 * Scans answer and authority sections of DNS packet to extract all RRs (Resource Records) matching
 * specified name/class/type into rrset array, and all covering RRSIG records into sigs array.
 * Validates that all RRSIGs have same signer name (keyname) per RFC 4035 Section 5.3.1. Enforces
 * that RRSIG signer name equals or encloses RRset owner name to prevent cross-zone signature
 * attacks. Dynamically expands rrset and sigs arrays via expand_workspace() as needed. Populates
 * sigcnt and rrcnt with counts for subsequent validation by validate_rrset(). This is the first
 * step in DNSSEC validation pipeline: explore → sort → validate.
 *
 * @param header DNS packet header to scan for RRs and RRSIGs
 * @param plen Packet length in bytes for bounds checking
 * @param class DNS class filter (e.g., C_IN for Internet class). Only RRs matching this class
 *              are included.
 * @param type DNS RR type filter (e.g., T_A, T_AAAA, T_MX). Only RRs and RRSIGs covering this
 *             type are included.
 * @param name Owner name filter in presentation format. Only RRs with this name are included.
 *             Used as workspace, unchanged on exit. Must be at least MAXDNAME bytes.
 * @param keyname Output buffer for RRSIG signer name, extracted from first RRSIG found. All
 *                subsequent RRSIGs must have same signer name or validation fails. Must be at
 *                least MAXDNAME bytes. Used as workspace, trashed on exit.
 * @param sigcnt Output: number of covering RRSIG records found and stored in sigs array
 * @param rrcnt Output: number of RRs found and stored in rrset array
 *
 * @return Success/failure indicator
 * @retval 1 Success: RRset and RRSIGs extracted, counts populated, signer name validated
 * @retval 0 Failure: bad packet format, name extraction error, inconsistent signer names,
 *           signer name does not enclose RRset name, memory allocation failure, short packet
 *
 * @note Uses static arrays rrset and sigs for storage, dynamically expanded as needed.
 * @note Scans answer section (ancount RRs) and authority section (nscount RRs), ignoring
 *       additional section.
 * @note Enforces RFC 4035 Section 5.3.1: RRSIG signer name MUST equal or enclose RRset owner
 *       name, preventing attacker from using key from unrelated zone. Root key (empty name)
 *       always allowed.
 * @note Minimal RRSIG length check: rdlen < 18 rejected (18 bytes = fixed RRSIG fields before
 *       signer name).
 *
 * @warning Modifies static rrset and sigs arrays. Not thread-safe. Not reentrant.
 * @warning keyname buffer trashed during processing, only valid signer name on success.
 * @warning name buffer used as workspace but unchanged on exit.
 *
 * @see validate_rrset() which uses explore_rrset() output for signature verification
 * @see expand_workspace() for dynamic array expansion
 * @see RFC 4035 Section 5.3.1 for RRSIG signer name validation requirements
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME] = "www.example.com";
 * char keyname[MAXDNAME];
 * int sigcnt, rrcnt;
 * if (explore_rrset(header, plen, C_IN, T_A, name, keyname, &sigcnt, &rrcnt)) {
 *     // Found rrcnt A records and sigcnt covering RRSIGs, signer is keyname
 *     // Proceed to validate_rrset()
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4035 Section 5.3.1 RRSIG signer name validation. Extracts
 * type-covered field from RRSIG per RFC 4034 Section 3.1.2.
 *
 * SIDE EFFECTS:
 * - Populates static rrset array with pointers to RRs in packet
 * - Populates static sigs array with pointers to RRSIG RDATA in packet
 * - May expand rrset and sigs arrays via expand_workspace()
 * - Trashes keyname buffer contents
 * - Sets *sigcnt and *rrcnt output parameters
 *
 * THREAD SAFETY: NOT thread-safe. Uses static rrset and sigs arrays. Not reentrant.
 */
static int explore_rrset(struct dns_header *header, size_t plen, int class, int type, 
			 char *name, char *keyname, int *sigcnt, int *rrcnt)
{
  static int rrset_sz = 0, sig_sz = 0; 
  unsigned char *p;
  int rrsetidx, sigidx, j, rdlen, res;
  int gotkey = 0;

  if (!(p = skip_questions(header, plen)))
    return 0;

   /* look for RRSIGs for this RRset and get pointers to each RR in the set. */
  for (rrsetidx = 0, sigidx = 0, j = ntohs(header->ancount) + ntohs(header->nscount); 
       j != 0; j--) 
    {
      unsigned char *pstart, *pdata;
      int stype, sclass, type_covered;

      pstart = p;
      
      if (!(res = extract_name(header, plen, &p, name, 0, 10)))
	return 0; /* bad packet */
      
      GETSHORT(stype, p);
      GETSHORT(sclass, p);
           
      pdata = p;

      p += 4; /* TTL */
      GETSHORT(rdlen, p);
      
      if (!CHECK_LEN(header, p, plen, rdlen))
	return 0; 
      
      if (res == 1 && sclass == class)
	{
	  if (stype == type)
	    {
	      if (!expand_workspace(&rrset, &rrset_sz, rrsetidx))
		return 0; 
	      
	      rrset[rrsetidx++] = pstart;
	    }
	  
	  if (stype == T_RRSIG)
	    {
	      if (rdlen < 18)
		return 0; /* bad packet */ 
	      
	      GETSHORT(type_covered, p);
	      p += 16; /* algo, labels, orig_ttl, sig_expiration, sig_inception, key_tag */
	      
	      if (gotkey)
		{
		  /* If there's more than one SIG, ensure they all have same keyname */
		  if (extract_name(header, plen, &p, keyname, 0, 0) != 1)
		    return 0;
		}
	      else
		{
		  gotkey = 1;
		  
		  if (!extract_name(header, plen, &p, keyname, 1, 0))
		    return 0;
		  
		  /* RFC 4035 5.3.1 says that the Signer's Name field MUST equal
		     the name of the zone containing the RRset. We can't tell that
		     for certain, but we can check that  the RRset name is equal to
		     or encloses the signers name, which should be enough to stop 
		     an attacker using signatures made with the key of an unrelated 
		     zone he controls. Note that the root key is always allowed. */
		  if (*keyname != 0)
		    {
		      char *name_start;
		      for (name_start = name; !hostname_isequal(name_start, keyname); )
			if ((name_start = strchr(name_start, '.')))
			  name_start++; /* chop a label off and try again */
			else
			  return 0;
		    }
		}
		  
	      
	      if (type_covered == type)
		{
		  if (!expand_workspace(&sigs, &sig_sz, sigidx))
		    return 0; 
		  
		  sigs[sigidx++] = pdata;
		} 
	      
	      p = pdata + 6; /* restore for ADD_RDLEN */
	    }
	}
      
      if (!ADD_RDLEN(header, p, plen, rdlen))
	return 0;
    }
  
  *sigcnt = sigidx;
  *rrcnt = rrsetidx;

  return 1;
}

/**
 * @brief Validate RRset cryptographic signatures using DNSKEY
 *
 * @detailed
 * Core DNSSEC validation function that cryptographically verifies RRSIG signatures over an RRset
 * using DNSKEY public keys. Sorts RRset into canonical order per RFC 4034 Section 6.3, constructs
 * signature validation data per RFC 4034 Section 3.1.8, computes hash digest, and verifies
 * signature via crypto.c primitives. Checks RRSIG inception/expiration timestamps using
 * serial_compare_32() for RFC 1982 arithmetic. Detects wildcard expansion per RFC 4035 Section 5.3.
 * Iterates through all RRSIGs until one validates successfully. Returns STAT_NEED_KEY if DNSKEY
 * not in cache. Computes TTL floor from RRSIG original_ttl and expiration time per RFC 4035
 * Section 5.3.3.
 *
 * @param now Current time for cache lookups and timestamp validation
 * @param header DNS packet header containing RRset and RRSIGs
 * @param plen Packet length in bytes for bounds checking
 * @param class DNS class (e.g., C_IN) for validation
 * @param type DNS RR type (e.g., T_A, T_AAAA) for validation
 * @param sigidx Number of RRSIG records in sigs array (from explore_rrset())
 * @param rrsetidx Number of RRs in rrset array (from explore_rrset())
 * @param name RRset owner name in presentation format, unchanged on exit. Used for wildcard
 *             detection via label counting.
 * @param keyname Workspace buffer for DNSKEY owner name extraction, trashed on exit. Must be
 *                at least MAXDNAME bytes.
 * @param wildcard_out Output pointer for wildcard expansion detection. Set to point within name
 *                     buffer at wildcard body if STAT_SECURE_WILDCARD returned, else NULL.
 * @param key Optional DNSKEY public key data. If non-NULL, use this key instead of cache lookup.
 *            Must match algo_in and keytag_in. If NULL, lookup key in cache.
 * @param keylen Length of key data in bytes if key is non-NULL
 * @param algo_in Expected DNSSEC algorithm number if key is non-NULL (e.g., 8 for RSA/SHA-256)
 * @param keytag_in Expected key tag if key is non-NULL
 * @param ttl_out Output TTL floor computed from RRSIG original_ttl and expiration time per
 *                RFC 4035 Section 5.3.3. Minimum of RRset TTL and signature-derived TTL.
 *
 * @return Validation status code
 * @retval STAT_SECURE RRset validates successfully with valid signature
 * @retval STAT_SECURE_WILDCARD RRset validates and is result of wildcard expansion per RFC 4035
 *         Section 5.3.2. *wildcard_out points to wildcard body within name.
 * @retval STAT_BOGUS Signature is invalid, bad packet format, or validation failed
 * @retval STAT_NEED_KEY DNSKEY required for validation not in cache. keyname contains signer name.
 * @retval STAT_NEED_DS DS record required (not used by this function, returned by callers)
 *
 * @note MUST call explore_rrset() first to populate sigidx, rrsetidx, and static rrset/sigs arrays.
 * @note Sorts rrset in place via sort_rrset() for canonical ordering.
 * @note Tries all RRSIGs sequentially until one validates or all fail.
 * @note Timestamp checking skipped if is_check_date() returns false (unreliable system time).
 * @note Wildcard detection per RFC 4035 Section 5.3.2: RRSIG labels field < owner name label count.
 * @note Supported algorithms depend on hash_find() and verify_*() functions in crypto.c.
 *
 * @warning Requires explore_rrset() called first to populate rrset and sigs arrays.
 * @warning keyname buffer trashed during RRSIG signer name extraction.
 * @warning Uses daemon->workspacename and keyname as temporary buffers in sort_rrset().
 * @warning Signature verification is CPU-intensive (RSA/ECDSA operations).
 *
 * @see explore_rrset() which must be called first to extract RRset and RRSIGs
 * @see sort_rrset() for canonical RRset ordering
 * @see serial_compare_32() for RFC 1982 timestamp comparison
 * @see is_check_date() for timestamp validation policy
 * @see verify_sha256(), verify_ecdsa() in crypto.c for signature verification
 * @see RFC 4034 Section 3.1.8 for signature verification procedure
 * @see RFC 4034 Section 6.3 for canonical RRset form
 * @see RFC 4035 Section 5.3 for validation algorithm
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME], keyname[MAXDNAME], *wildcard;
 * unsigned long ttl;
 * int sigcnt, rrcnt;
 * explore_rrset(header, plen, C_IN, T_A, name, keyname, &sigcnt, &rrcnt);
 * int result = validate_rrset(now, header, plen, C_IN, T_A, sigcnt, rrcnt,
 *                              name, keyname, &wildcard, NULL, 0, 0, 0, &ttl);
 * if (result == STAT_SECURE) {
 *     // Signature valid, cache answer with ttl
 * } else if (result == STAT_NEED_KEY) {
 *     // Fetch DNSKEY for keyname
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4035 Section 5.3 DNSSEC validation algorithm, RFC 4034 Section
 * 3.1.8 signature verification, RFC 4034 Section 6.3 canonical RRset form, RFC 4035 Section 5.3.2
 * wildcard expansion detection, RFC 4035 Section 5.3.3 TTL floor calculation.
 *
 * SIDE EFFECTS:
 * - Calls sort_rrset() which reorders static rrset array
 * - Trashes keyname buffer
 * - Sets *wildcard_out if wildcard detected
 * - Sets *ttl_out with computed TTL floor
 * - May allocate hash context via hash_init()
 * - Performs cache lookup via cache_find_by_name() if key is NULL
 *
 * THREAD SAFETY: NOT thread-safe. Uses static rrset/sigs arrays from explore_rrset(). Not
 * reentrant.
 */
static int validate_rrset(time_t now, struct dns_header *header, size_t plen, int class, int type, int sigidx, int rrsetidx, 
			  char *name, char *keyname, char **wildcard_out, struct blockdata *key, int keylen,
			  int algo_in, int keytag_in, unsigned long *ttl_out)
{
  unsigned char *p;
  int rdlen, j, name_labels, algo, labels, key_tag;
  struct crec *crecp = NULL;
  u16 *rr_desc = rrfilter_desc(type);
  u32 sig_expiration, sig_inception;
  int failflags = DNSSEC_FAIL_NOSIG | DNSSEC_FAIL_NYV | DNSSEC_FAIL_EXP | DNSSEC_FAIL_NOKEYSUP;
  
  unsigned long curtime = time(0);
  int time_check = is_check_date(curtime);
  
  if (wildcard_out)
    *wildcard_out = NULL;
  
  name_labels = count_labels(name); /* For 4035 5.3.2 check */

  /* Sort RRset records into canonical order. 
     Note that at this point keyname and daemon->workspacename buffs are
     unused, and used as workspace by the sort. */
  rrsetidx = sort_rrset(header, plen, rr_desc, rrsetidx, rrset, daemon->workspacename, keyname);
         
  /* Now try all the sigs to try and find one which validates */
  for (j = 0; j <sigidx; j++)
    {
      unsigned char *psav, *sig, *digest;
      int i, wire_len, sig_len;
      const struct nettle_hash *hash;
      void *ctx;
      char *name_start;
      u32 nsigttl, ttl, orig_ttl;

      failflags &= ~DNSSEC_FAIL_NOSIG;
      
      p = sigs[j];
      GETLONG(ttl, p);
      GETSHORT(rdlen, p); /* rdlen >= 18 checked previously */
      psav = p;
      
      p += 2; /* type_covered - already checked */
      algo = *p++;
      labels = *p++;
      GETLONG(orig_ttl, p);
      GETLONG(sig_expiration, p);
      GETLONG(sig_inception, p);
      GETSHORT(key_tag, p);
      
      if (!extract_name(header, plen, &p, keyname, 1, 0))
	return STAT_BOGUS;

      if (!time_check)
	failflags &= ~(DNSSEC_FAIL_NYV | DNSSEC_FAIL_EXP);
      else
	{
	  /* We must explicitly check against wanted values, because of SERIAL_UNDEF */
	  if (serial_compare_32(curtime, sig_inception) == SERIAL_LT)
	    continue;
	  else
	    failflags &= ~DNSSEC_FAIL_NYV;
	  
	  if (serial_compare_32(curtime, sig_expiration) == SERIAL_GT)
	    continue;
	  else
	    failflags &= ~DNSSEC_FAIL_EXP;
	}

      if (!(hash = hash_find(algo_digest_name(algo))))
	continue;
      else
	failflags &= ~DNSSEC_FAIL_NOKEYSUP;
      
      if (labels > name_labels ||
	  !hash_init(hash, &ctx, &digest))
	continue;
      
      /* OK, we have the signature record, see if the relevant DNSKEY is in the cache. */
      if (!key && !(crecp = cache_find_by_name(NULL, keyname, now, F_DNSKEY)))
	return STAT_NEED_KEY;

       if (ttl_out)
	 {
	   /* 4035 5.3.3 rules on TTLs */
	   if (orig_ttl < ttl)
	     ttl = orig_ttl;
	   
	   if (time_check && difftime(sig_expiration, curtime) < ttl)
	     ttl = difftime(sig_expiration, curtime);

	   *ttl_out = ttl;
	 }
       
      sig = p;
      sig_len = rdlen - (p - psav);
              
      nsigttl = htonl(orig_ttl);
      
      hash->update(ctx, 18, psav);
      wire_len = to_wire(keyname);
      hash->update(ctx, (unsigned int)wire_len, (unsigned char*)keyname);
      from_wire(keyname);

#define RRBUFLEN 128 /* Most RRs are smaller than this. */
      
      for (i = 0; i < rrsetidx; ++i)
	{
	  int j;
	  struct rdata_state state;
	  u16 len;
	  unsigned char rrbuf[RRBUFLEN];
	  
	  p = rrset[i];
	  
	  if (!extract_name(header, plen, &p, name, 1, 10)) 
	    return STAT_BOGUS;

	  name_start = name;
	  
	  /* if more labels than in RRsig name, hash *.<no labels in rrsig labels field>  4035 5.3.2 */
	  if (labels < name_labels)
	    {
	      for (j = name_labels - labels; j != 0; j--)
		{
		  while (*name_start != '.' && *name_start != 0)
		    name_start++;
		  if (j != 1 && *name_start == '.')
		    name_start++;
		}
	      
	      if (wildcard_out)
		*wildcard_out = name_start+1;

	      name_start--;
	      *name_start = '*';
	    }
	  
	  wire_len = to_wire(name_start);
	  hash->update(ctx, (unsigned int)wire_len, (unsigned char *)name_start);
	  hash->update(ctx, 4, p); /* class and type */
	  hash->update(ctx, 4, (unsigned char *)&nsigttl);

	  p += 8; /* skip type, class, ttl */
	  GETSHORT(rdlen, p);
	  if (!CHECK_LEN(header, p, plen, rdlen))
	    return STAT_BOGUS; 

	  /* Optimisation for RR types which need no cannonicalisation.
	     This includes DNSKEY DS NSEC and NSEC3, which are also long, so
	     it saves lots of calls to get_rdata, and avoids the pessimal
	     segmented insertion, even with a small rrbuf[].
	     
	     If canonicalisation is not needed, a simple insertion into the hash works.
	  */
	  if (*rr_desc == (u16)-1)
	    {
	      len = htons(rdlen);
	      hash->update(ctx, 2, (unsigned char *)&len);
	      hash->update(ctx, rdlen, p);
	    }
	  else
	    {
	      /* canonicalise rdata and calculate length of same, use 
		 name buffer as workspace for get_rdata. */
	      state.ip = p;
	      state.op = NULL;
	      state.desc = rr_desc;
	      state.buff = name;
	      state.end = p + rdlen;
	      
	      for (j = 0; get_rdata(header, plen, &state); j++)
		if (j < RRBUFLEN)
		  rrbuf[j] = *state.op;
	      
	      len = htons((u16)j);
	      hash->update(ctx, 2, (unsigned char *)&len); 
	      
	      /* If the RR is shorter than RRBUFLEN (most of them, in practice)
		 then we can just digest it now. If it exceeds RRBUFLEN we have to
		 go back to the start and do it in chunks. */
	      if (j >= RRBUFLEN)
		{
		  state.ip = p;
		  state.op = NULL;
		  state.desc = rr_desc;
		  
		  for (j = 0; get_rdata(header, plen, &state); j++)
		    {
		      rrbuf[j] = *state.op;
		      
		      if (j == RRBUFLEN - 1)
			{
			  hash->update(ctx, RRBUFLEN, rrbuf);
			  j = -1;
			}
		    }
		}
	      
	      if (j != 0)
		hash->update(ctx, j, rrbuf);
	    }
	}
     
      hash->digest(ctx, hash->digest_size, digest);
      
      /* namebuff used for workspace above, restore to leave unchanged on exit */
      p = (unsigned char*)(rrset[0]);
      if (!extract_name(header, plen, &p, name, 1, 0))
	return STAT_BOGUS;

      if (key)
	{
	  if (algo_in == algo && keytag_in == key_tag &&
	      verify(key, keylen, sig, sig_len, digest, hash->digest_size, algo))
	    return STAT_SECURE;
	}
      else
	{
	  /* iterate through all possible keys 4035 5.3.1 */
	  for (; crecp; crecp = cache_find_by_name(crecp, keyname, now, F_DNSKEY))
	    if (crecp->addr.key.algo == algo && 
		crecp->addr.key.keytag == key_tag &&
		crecp->uid == (unsigned int)class &&
		verify(crecp->addr.key.keydata, crecp->addr.key.keylen, sig, sig_len, digest, hash->digest_size, algo))
	      return (labels < name_labels) ? STAT_SECURE_WILDCARD : STAT_SECURE;
	}
    }

  /* If we reach this point, no verifying key was found */
  return STAT_BOGUS | failflags | DNSSEC_FAIL_NOKEY;
}
 

/* The DNS packet is expected to contain the answer to a DNSKEY query.
   Put all DNSKEYs in the answer which are valid into the cache.
   return codes:
         STAT_OK        Done, key(s) in cache.
	 STAT_BOGUS     No DNSKEYs found, which  can be validated with DS,
	                or self-sign for DNSKEY RRset is not valid, bad packet.
	 STAT_NEED_DS   DS records to validate a key not found, name in keyname 
	 STAT_NEED_KEY  DNSKEY records to validate a key not found, name in keyname 
*/

/**
 * @brief Validate DNSKEY RRset against parent zone DS records
 *
 * @detailed
 * Validates DNSKEY records in DNS response against cached DS (Delegation Signer) records from
 * parent zone, establishing trust for zone's public keys per RFC 4035 Section 5.2. Computes digest
 * hash over DNSKEY (owner name + RDATA) and compares to DS digest field. If match found, validates
 * DNSKEY RRset signatures using the matched key via validate_rrset(). This establishes the trust
 * chain: parent DS → child DNSKEY → child zone data. Supports multiple hash algorithms (SHA-1,
 * SHA-256, SHA-384, GOST) as specified by DS digest type. Checks DNSKEY zone flag (bit 7) to
 * ensure key is authorized for zone signing. Returns STAT_NEED_DS if parent DS not cached,
 * triggering recursive DS fetch.
 *
 * @param now Current time for cache lookups and timestamp validation
 * @param header DNS packet header containing DNSKEY answer to query for zone's DNSKEY RRset.
 *               MUST have exactly one question, ancount > 0. RCODE must not be SERVFAIL/REFUSED.
 * @param plen Packet length in bytes for bounds checking
 * @param name Zone name for DNSKEY query, in presentation format. Modified during name extraction,
 *             restored on loop iterations. Must be at least MAXDNAME bytes.
 * @param keyname Output buffer for DS query name if STAT_NEED_DS returned. Set to zone name.
 *                Used as workspace during validation. Must be at least MAXDNAME bytes.
 * @param class DNS class (e.g., C_IN) for validation
 *
 * @return Validation status with failure flags
 * @retval STAT_SECURE DNSKEY RRset validates against DS, trust established
 * @retval STAT_BOGUS Invalid packet format, DNSKEY doesn't match DS digest, signature invalid
 * @retval STAT_NEED_DS DS record not cached, need to fetch DS for zone. keyname contains zone name.
 * @retval STAT_NEED_KEY DNSKEY needed for RRSIG validation (from validate_rrset())
 * @retval (status | failflags) Validation failure with diagnostic flags: DNSSEC_FAIL_NOKEY (no
 *         valid DNSKEY), DNSSEC_FAIL_NOSIG (no RRSIG), DNSSEC_FAIL_NODSSUP (unsupported DS digest),
 *         DNSSEC_FAIL_NOZONE (no zone key flag set)
 *
 * @note Packet MUST be response to DNSKEY query (qtype == T_DNSKEY, ancount > 0).
 * @note Requires parent DS record cached via F_DS flag. If not found, returns STAT_NEED_DS.
 * @note DNSKEY zone flag (0x100, bit 7) MUST be set or key is rejected per RFC 4034 Section 2.1.1.
 * @note Tries ALL DNSKEYs in answer until one matches DS digest and validates RRset.
 * @note DS digest computed as: HASH(owner_name_wire + DNSKEY_RDATA) per RFC 4034 Section 5.1.4.
 * @note Supported DS digest types depend on hash_find() in crypto.c: 1=SHA-1, 2=SHA-256, 3=GOST,
 *       4=SHA-384.
 *
 * @warning Packet must have exactly one question (qdcount == 1) or returns STAT_BOGUS.
 * @warning RCODE must not be SERVFAIL or REFUSED or returns STAT_BOGUS.
 * @warning DNSKEY RDATA must be at least 4 bytes (flags + protocol + algorithm) or returns
 *          STAT_BOGUS.
 * @warning Memory allocated via blockdata_alloc() for key data, freed on error or after use.
 *
 * @see dnssec_validate_ds() for validating DS records themselves
 * @see validate_rrset() called to verify DNSKEY RRset signatures
 * @see dnskey_keytag() for computing DNSKEY key tag
 * @see RFC 4034 Section 5.1.4 for DS digest computation
 * @see RFC 4034 Section 2.1.1 for DNSKEY flags (zone key bit 7)
 * @see RFC 4035 Section 5.2 for authenticating referrals and DNSKEY RRsets
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME] = "example.com";
 * char keyname[MAXDNAME];
 * int result = dnssec_validate_by_ds(now, header, plen, name, keyname, C_IN);
 * if (result == STAT_SECURE) {
 *     // DNSKEY validates, trust established for example.com zone
 * } else if (result == STAT_NEED_DS) {
 *     // Need to fetch DS record for example.com from parent (com)
 *     fetch_ds(keyname);  // keyname contains "example.com"
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4035 Section 5.2 authenticating referrals, RFC 4034 Section 5.1.4
 * DS resource record digest computation, RFC 4034 Section 2.1.1 DNSKEY zone key flag validation.
 *
 * SIDE EFFECTS:
 * - Modifies name buffer during name extraction (restored on loops)
 * - Allocates blockdata via blockdata_alloc() for DNSKEY public key
 * - Frees blockdata via blockdata_free() after validation or on error
 * - Performs cache lookup via cache_find_by_name() for DS records
 * - Calls validate_rrset() which uses static rrset/sigs arrays
 * - Calls explore_rrset() internally via validate_rrset() path
 * - Computes digest via hash_init() and hash functions
 *
 * THREAD SAFETY: NOT thread-safe. Calls validate_rrset() which uses static arrays. Not reentrant.
 */
int dnssec_validate_by_ds(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int class)
{
  unsigned char *psave, *p = (unsigned char *)(header+1);
  struct crec *crecp, *recp1;
  int rc, j, qtype, qclass, rdlen, flags, algo, valid, keytag;
  unsigned long ttl, sig_ttl;
  struct blockdata *key;
  union all_addr a;
  int failflags = DNSSEC_FAIL_NOSIG | DNSSEC_FAIL_NODSSUP | DNSSEC_FAIL_NOZONE | DNSSEC_FAIL_NOKEY;

  if (ntohs(header->qdcount) != 1 ||
      RCODE(header) == SERVFAIL || RCODE(header) == REFUSED ||
      !extract_name(header, plen, &p, name, 1, 4))
    return STAT_BOGUS | DNSSEC_FAIL_NOKEY;

  GETSHORT(qtype, p);
  GETSHORT(qclass, p);
  
  if (qtype != T_DNSKEY || qclass != class || ntohs(header->ancount) == 0)
    return STAT_BOGUS | DNSSEC_FAIL_NOKEY;

  /* See if we have cached a DS record which validates this key */
  if (!(crecp = cache_find_by_name(NULL, name, now, F_DS)))
    {
      strcpy(keyname, name);
      return STAT_NEED_DS;
    }
  
  /* NOTE, we need to find ONE DNSKEY which matches the DS */
  for (valid = 0, j = ntohs(header->ancount); j != 0 && !valid; j--) 
    {
      /* Ensure we have type, class  TTL and length */
      if (!(rc = extract_name(header, plen, &p, name, 0, 10)))
	return STAT_BOGUS; /* bad packet */
  
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
 
      if (!CHECK_LEN(header, p, plen, rdlen) || rdlen < 4)
	return STAT_BOGUS; /* bad packet */
      
      if (qclass != class || qtype != T_DNSKEY || rc == 2)
	{
	  p += rdlen;
	  continue;
	}
            
      psave = p;
      
      GETSHORT(flags, p);
      if (*p++ != 3)
	return STAT_BOGUS | DNSSEC_FAIL_NOKEY;
      algo = *p++;
      keytag = dnskey_keytag(algo, flags, p, rdlen - 4);
      key = NULL;
      
      /* key must have zone key flag set */
      if (flags & 0x100)
	{
	  key = blockdata_alloc((char*)p, rdlen - 4);
	  failflags &= ~DNSSEC_FAIL_NOZONE;
	}
      
      p = psave;
      
      if (!ADD_RDLEN(header, p, plen, rdlen))
	{
	  if (key)
	    blockdata_free(key);
	  return STAT_BOGUS; /* bad packet */
	}

      /* No zone key flag or malloc failure */
      if (!key)
	continue;
      
      for (recp1 = crecp; recp1; recp1 = cache_find_by_name(recp1, name, now, F_DS))
	{
	  void *ctx;
	  unsigned char *digest, *ds_digest;
	  const struct nettle_hash *hash;
	  int sigcnt, rrcnt;
	  int wire_len;
	  
	  if (recp1->addr.ds.algo == algo && 
	      recp1->addr.ds.keytag == keytag &&
	      recp1->uid == (unsigned int)class)
	    {
	      failflags &= ~DNSSEC_FAIL_NOKEY;
	      
	      if (!(hash = hash_find(ds_digest_name(recp1->addr.ds.digest))))
		continue;
	      else
		failflags &= ~DNSSEC_FAIL_NODSSUP;

	      if (!hash_init(hash, &ctx, &digest))
		continue;
	      
	      wire_len = to_wire(name);
	      
	      /* Note that digest may be different between DSs, so 
		 we can't move this outside the loop. */
	      hash->update(ctx, (unsigned int)wire_len, (unsigned char *)name);
	      hash->update(ctx, (unsigned int)rdlen, psave);
	      hash->digest(ctx, hash->digest_size, digest);
	      
	      from_wire(name);
	      
	      if (!(recp1->flags & F_NEG) &&
		  recp1->addr.ds.keylen == (int)hash->digest_size &&
		  (ds_digest = blockdata_retrieve(recp1->addr.ds.keydata, recp1->addr.ds.keylen, NULL)) &&
		  memcmp(ds_digest, digest, recp1->addr.ds.keylen) == 0 &&
		  explore_rrset(header, plen, class, T_DNSKEY, name, keyname, &sigcnt, &rrcnt) &&
		  rrcnt != 0)
		{
		  if (sigcnt == 0)
		    continue;
		  else
		    failflags &= ~DNSSEC_FAIL_NOSIG;
		  
		  rc = validate_rrset(now, header, plen, class, T_DNSKEY, sigcnt, rrcnt, name, keyname, 
				      NULL, key, rdlen - 4, algo, keytag, &sig_ttl);

		  failflags &= rc;
		  
		  if (STAT_ISEQUAL(rc, STAT_SECURE))
		    {
		      valid = 1;
		      break;
		    }
		}
	    }
	}
      blockdata_free(key);
    }

  if (valid)
    {
      /* DNSKEY RRset determined to be OK, now cache it. */
      cache_start_insert();
      
      p = skip_questions(header, plen);

      for (j = ntohs(header->ancount); j != 0; j--) 
	{
	  /* Ensure we have type, class  TTL and length */
	  if (!(rc = extract_name(header, plen, &p, name, 0, 10)))
	    return STAT_BOGUS; /* bad packet */
	  
	  GETSHORT(qtype, p); 
	  GETSHORT(qclass, p);
	  GETLONG(ttl, p);
	  GETSHORT(rdlen, p);

	  /* TTL may be limited by sig. */
	  if (sig_ttl < ttl)
	    ttl = sig_ttl;
	    
	  if (!CHECK_LEN(header, p, plen, rdlen))
	    return STAT_BOGUS; /* bad packet */
	  
	  if (qclass == class && rc == 1)
	    {
	      psave = p;
	      
	      if (qtype == T_DNSKEY)
		{
		  if (rdlen < 4)
		    return STAT_BOGUS; /* bad packet */
		  
		  GETSHORT(flags, p);
		  if (*p++ != 3)
		    return STAT_BOGUS;
		  algo = *p++;
		  keytag = dnskey_keytag(algo, flags, p, rdlen - 4);
		  
		  if ((key = blockdata_alloc((char*)p, rdlen - 4)))
		    {
		      a.key.keylen = rdlen - 4;
		      a.key.keydata = key;
		      a.key.algo = algo;
		      a.key.keytag = keytag;
		      a.key.flags = flags;
		      
		      if (!cache_insert(name, &a, class, now, ttl, F_FORWARD | F_DNSKEY | F_DNSSECOK))
			{
			  blockdata_free(key);
			  return STAT_BOGUS;
			}
		      else
			{
			  a.log.keytag = keytag;
			  a.log.algo = algo;
			  if (algo_digest_name(algo))
			    log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DNSKEY keytag %hu, algo %hu", 0);
			  else
			    log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DNSKEY keytag %hu, algo %hu (not supported)", 0);
			}
		    }
		}
	      	      
	      p = psave;
	    }

	  if (!ADD_RDLEN(header, p, plen, rdlen))
	    return STAT_BOGUS; /* bad packet */
	}
      
      /* commit cache insert. */
      cache_end_insert();
      return STAT_OK;
    }

  log_query(F_NOEXTRA | F_UPSTREAM, name, NULL, "BOGUS DNSKEY", 0);
  return STAT_BOGUS | failflags;
}

/* The DNS packet is expected to contain the answer to a DS query
   Put all DSs in the answer which are valid into the cache.
   Also handles replies which prove that there's no DS at this location, 
   either because the zone is unsigned or this isn't a zone cut. These are
   cached too.
   return codes:
   STAT_OK          At least one valid DS found and in cache.
   STAT_BOGUS       no DS in reply or not signed, fails validation, bad packet.
   STAT_NEED_KEY    DNSKEY records to validate a DS not found, name in keyname
   STAT_NEED_DS     DS record needed.
*/

/**
 * @brief Validate DS records by verifying their DNSKEY signatures in child zone
 *
 * @detailed
 * Validates DS (Delegation Signer) records in parent zone by checking signatures using DNSKEY
 * from child zone per RFC 4035 Section 5.2. Calls dnssec_validate_reply() to perform full
 * validation of DS RRset including RRSIG verification. Handles negative answers (no DS, proving
 * insecure delegation) and positive DS answers. Caches validated DS records with F_DS flag for
 * use by dnssec_validate_by_ds(). Detects insecure DS replies and treats as BOGUS to prevent
 * downgrade attacks. Detects validation loops where DS and DNSKEY are in same zone (misconfiguration).
 * Successfully validated DS records enable building chain of trust from parent to child zone.
 *
 * @param now Current time for cache lookups and timestamp validation
 * @param header DNS packet header containing DS answer from parent zone. MUST have exactly one
 *               question (qdcount == 1), qtype == T_DS. May have positive DS answer or negative
 *               answer (NSEC/NSEC3 proofs).
 * @param plen Packet length in bytes for bounds checking
 * @param name Zone name for DS query, in presentation format. Modified during processing. Must be
 *             at least MAXDNAME bytes.
 * @param keyname Workspace buffer for DNSKEY signer name during validation. Output buffer for
 *                STAT_NEED_KEY case. Must be at least MAXDNAME bytes.
 * @param class DNS class (e.g., C_IN) for validation
 *
 * @return Validation status
 * @retval STAT_SECURE DS RRset validates successfully, records cached with F_DS flag
 * @retval STAT_BOGUS Invalid packet, DS validation failed, or insecure DS reply detected.
 *         Insecure DS replies logged as warnings and treated as bogus to prevent attacks.
 * @retval STAT_NEED_KEY DNSKEY needed for DS RRset signature validation. keyname contains signer.
 * @retval STAT_NEED_DS Additional DS needed (propagated from dnssec_validate_reply())
 *
 * @note Packet MUST be response to DS query (qtype == T_DS, qdcount == 1).
 * @note Delegates to dnssec_validate_reply() for actual validation work.
 * @note Insecure DS (STAT_INSECURE) converted to STAT_BOGUS with warning log. Prevents downgrade
 *       attacks where attacker provides insecure DS to break chain of trust.
 * @note Detects validation loop: if STAT_NEED_KEY and keyname == name, DS and DNSKEY are in same
 *       zone (misconfiguration). Returns STAT_BOGUS to prevent infinite recursion.
 * @note On success with positive answer, caches DS records with F_DS flag, algorithm, keytag, and
 *       digest for use by dnssec_validate_by_ds().
 * @note Negative answers (no DS, NSEC/NSEC3 proof) also cached with F_DS | F_NEG flags, indicating
 *       insecure delegation.
 *
 * @warning Insecure DS reply (STAT_INSECURE) triggers syslog warning and is treated as BOGUS.
 * @warning Validation loop (DS in same zone as DNSKEY) triggers log and returns STAT_BOGUS.
 * @warning Relies on dnssec_validate_reply() for packet validation and RRSIG verification.
 *
 * @see dnssec_validate_by_ds() which uses cached DS records from this function
 * @see dnssec_validate_reply() which performs full DS RRset validation
 * @see RFC 4035 Section 5.2 for DS record validation in trust chain
 * @see RFC 4034 Section 5 for DS resource record specification
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME] = "example.com";
 * char keyname[MAXDNAME];
 * int result = dnssec_validate_ds(now, header, plen, name, keyname, C_IN);
 * if (result == STAT_SECURE) {
 *     // DS records validated and cached, can now validate example.com DNSKEY
 * } else if (result == STAT_NEED_KEY) {
 *     // Need DNSKEY for keyname to validate DS signatures
 *     fetch_dnskey(keyname);
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4035 Section 5.2 authenticating referrals via DS records,
 * RFC 4035 Section 5.3 validation procedure for DS RRsets.
 *
 * SIDE EFFECTS:
 * - Modifies name and keyname buffers during processing
 * - Calls dnssec_validate_reply() with full validation side effects
 * - Caches validated DS records via cache_insert() with F_DS flag
 * - Caches negative DS answers with F_DS | F_NEG flags (insecure delegation)
 * - Logs warnings via my_syslog() for insecure DS replies
 * - Logs bogus DS via log_query() on validation failures
 * - Calls cache_start_insert() to begin cache insertion transaction
 * - Calls cache_end_insert() to commit cache transaction (in positive answer path)
 *
 * THREAD SAFETY: NOT thread-safe. Calls dnssec_validate_reply() which uses static arrays.
 * Not reentrant.
 */

int dnssec_validate_ds(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int class)
{
  unsigned char *p = (unsigned char *)(header+1);
  int qtype, qclass, rc, i, neganswer, nons, neg_ttl = 0;
  int aclass, atype, rdlen;
  unsigned long ttl;
  union all_addr a;

  if (ntohs(header->qdcount) != 1 ||
      !(p = skip_name(p, header, plen, 4)))
    return STAT_BOGUS;
  
  GETSHORT(qtype, p);
  GETSHORT(qclass, p);

  if (qtype != T_DS || qclass != class)
    rc = STAT_BOGUS;
  else
    rc = dnssec_validate_reply(now, header, plen, name, keyname, NULL, 0, &neganswer, &nons, &neg_ttl);
  
  if (STAT_ISEQUAL(rc, STAT_INSECURE))
    {
      my_syslog(LOG_WARNING, _("Insecure DS reply received for %s, check domain configuration and upstream DNS server DNSSEC support"), name);
      log_query(F_NOEXTRA | F_UPSTREAM, name, NULL, "BOGUS DS - not secure", 0);
      return STAT_BOGUS | DNSSEC_FAIL_INDET;
    }
  
  p = (unsigned char *)(header+1);
  if (!extract_name(header, plen, &p, name, 1, 4))
      return STAT_BOGUS;

  p += 4; /* qtype, qclass */
  
  /* If the key needed to validate the DS is on the same domain as the DS, we'll
     loop getting nowhere. Stop that now. This can happen of the DS answer comes
     from the DS's zone, and not the parent zone. */
  if (STAT_ISEQUAL(rc, STAT_NEED_KEY) && hostname_isequal(name, keyname))
    {
      log_query(F_NOEXTRA | F_UPSTREAM, name, NULL, "BOGUS DS", 0);
      return STAT_BOGUS;
    }
  
  if (!STAT_ISEQUAL(rc, STAT_SECURE))
    return rc;
   
  if (!neganswer)
    {
      cache_start_insert();
      
      for (i = 0; i < ntohs(header->ancount); i++)
	{
	  if (!(rc = extract_name(header, plen, &p, name, 0, 10)))
	    return STAT_BOGUS; /* bad packet */
	  
	  GETSHORT(atype, p);
	  GETSHORT(aclass, p);
	  GETLONG(ttl, p);
	  GETSHORT(rdlen, p);
	  
	  if (!CHECK_LEN(header, p, plen, rdlen))
	    return STAT_BOGUS; /* bad packet */
	  
	  if (aclass == class && atype == T_DS && rc == 1)
	    { 
	      int algo, digest, keytag;
	      unsigned char *psave = p;
	      struct blockdata *key;
	   
	      if (rdlen < 4)
		return STAT_BOGUS; /* bad packet */
	      
	      GETSHORT(keytag, p);
	      algo = *p++;
	      digest = *p++;
	      
	      if ((key = blockdata_alloc((char*)p, rdlen - 4)))
		{
		  a.ds.digest = digest;
		  a.ds.keydata = key;
		  a.ds.algo = algo;
		  a.ds.keytag = keytag;
		  a.ds.keylen = rdlen - 4;

		  if (!cache_insert(name, &a, class, now, ttl, F_FORWARD | F_DS | F_DNSSECOK))
		    {
		      blockdata_free(key);
		      return STAT_BOGUS;
		    }
		  else
		    {
		      a.log.keytag = keytag;
		      a.log.algo = algo;
		      a.log.digest = digest;
		      if (ds_digest_name(digest) && algo_digest_name(algo))
			log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DS keytag %hu, algo %hu, digest %hu", 0);
		      else
			log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a, "DS keytag %hu, algo %hu, digest %hu (not supported)", 0);
		    } 
		}
	      
	      p = psave;
	    }
	  if (!ADD_RDLEN(header, p, plen, rdlen))
	    return STAT_BOGUS; /* bad packet */
	}

      cache_end_insert();

    }
  else
    {
      int flags = F_FORWARD | F_DS | F_NEG | F_DNSSECOK;
            
      if (RCODE(header) == NXDOMAIN)
	flags |= F_NXDOMAIN;
      
      /* We only cache validated DS records, DNSSECOK flag hijacked 
	 to store presence/absence of NS. */
      if (nons)
	flags &= ~F_DNSSECOK;
      
      cache_start_insert();
	  
      /* Use TTL from NSEC for negative cache entries */
      if (!cache_insert(name, NULL, class, now, neg_ttl, flags))
	return STAT_BOGUS;
      
      cache_end_insert();  
      
      log_query(F_NOEXTRA | F_UPSTREAM, name, NULL, nons ? "no DS/cut" : "no DS", 0);
    }
      
  return STAT_OK;
}


/* 4034 6.1 */
/**
 * @brief Compare DNS names in canonical order for DNSSEC NSEC validation
 *
 * @detailed
 * Compares two DNS names in canonical order per RFC 4034 Section 6.1 for DNSSEC NSEC record
 * validation. Performs case-insensitive, right-to-left label-by-label comparison (TLD first,
 * then second-level domain, etc.). Labels compared lexicographically using lowercase ASCII.
 * This ordering is required for NSEC record chain validation: NSEC owner name must be less than
 * next_domain_name for valid denial of existence proof. Comparison starts from rightmost label
 * (root) and proceeds left, ensuring proper hierarchical DNS name ordering.
 *
 * @param a First DNS name in presentation format (dot-separated labels), NUL-terminated
 * @param b Second DNS name in presentation format (dot-separated labels), NUL-terminated
 *
 * @return Comparison result in canonical DNS name order
 * @retval -1 Name a is less than name b in canonical order
 * @retval 0 Names are equal (case-insensitive)
 * @retval 1 Name a is greater than name b in canonical order
 *
 * @note Comparison is case-insensitive: 'A'-'Z' normalized to 'a'-'z' before comparison.
 * @note Right-to-left label comparison ensures proper hierarchical ordering: "a.b.com" < "c.b.com"
 *       because "a" < "c" when comparing third labels.
 * @note Shorter names (fewer labels) sort before longer names with same prefix: "com" < "b.com".
 * @note Used by NSEC validation to verify name falls within NSEC owner and next domain span.
 *
 * @see prove_non_existence_nsec() which uses hostname_cmp() for NSEC chain validation
 * @see RFC 4034 Section 6.1 for canonical DNS name order specification
 *
 * EXAMPLE USAGE:
 * @code
 * int cmp1 = hostname_cmp("www.example.com", "mail.example.com");  // Returns -1 (www < mail)
 * int cmp2 = hostname_cmp("example.com", "Example.Com");           // Returns 0 (case-insensitive)
 * int cmp3 = hostname_cmp("example.com", "example.net");           // Returns -1 (com < net)
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4034 Section 6.1 canonical DNS name order for NSEC validation.
 *
 * SIDE EFFECTS: None (read-only comparison).
 *
 * THREAD SAFETY: Reentrant, no global state.
 */
static int hostname_cmp(const char *a, const char *b)
{
  char *sa, *ea, *ca, *sb, *eb, *cb;
  unsigned char ac, bc;
  
  sa = ea = (char *)a + strlen(a);
  sb = eb = (char *)b + strlen(b);
 
  while (1)
    {
      while (sa != a && *(sa-1) != '.')
	sa--;
      
      while (sb != b && *(sb-1) != '.')
	sb--;

      ca = sa;
      cb = sb;

      while (1) 
	{
	  if (ca == ea)
	    {
	      if (cb == eb)
		break;
	      
	      return -1;
	    }
	  
	  if (cb == eb)
	    return 1;
	  
	  ac = (unsigned char) *ca++;
	  bc = (unsigned char) *cb++;
	  
	  if (ac >= 'A' && ac <= 'Z')
	    ac += 'a' - 'A';
	  if (bc >= 'A' && bc <= 'Z')
	    bc += 'a' - 'A';
	  
	  if (ac < bc)
	    return -1;
	  else if (ac != bc)
	    return 1;
	}

     
      if (sa == a)
	{
	  if (sb == b)
	    return 0;
	  
	  return -1;
	}
      
      if (sb == b)
	return 1;
      
      ea = --sa;
      eb = --sb;
    }
}

/**
 * @brief Validate NSEC denial-of-existence proof per RFC 4034/4035
 *
 * @detailed
 * Validates NSEC-based authenticated denial of existence for negative answers (NXDOMAIN or NODATA)
 * per RFC 4034 Section 4 and RFC 4035 Section 5.4. Iterates through NSEC records from authority
 * section, checking if any NSEC covers the queried name (name falls between NSEC owner and next name).
 * For NXDOMAIN, validates name doesn't exist. For NODATA, validates name exists but type is not set
 * in NSEC type bitmap. Handles wildcard expansion by using original wildcard name (from RRSIG labels)
 * instead of expanded name. Performs canonicalized name comparison for DNSSEC ordering per RFC 4034
 * Section 6.1. Returns STAT_SECURE if proof valid, 0 if proof fails or is incomplete.
 *
 * @param header DNS packet header containing response with NSEC records
 * @param plen Packet length in bytes for bounds checking
 * @param nsecs Array of pointers to NSEC record start positions in packet. Each pointer points to
 *              NSEC owner name.
 * @param labels Array of RRSIG labels values corresponding to each NSEC. Used for wildcard expansion
 *               detection. labels[i] contains labels count from RRSIG covering nsecs[i].
 * @param nsec_count Number of NSEC records in nsecs array
 * @param workspace1_in Temporary buffer for NSEC owner name extraction (MAXDNAME size)
 * @param workspace2 Temporary buffer for NSEC next name extraction (MAXDNAME size)
 * @param name Query name to prove non-existence, presentation format
 * @param type Query type for NODATA proof (e.g., T_A=1, T_AAAA=28). For NXDOMAIN, type is ignored.
 * @param nons Optional output flag for empty NSEC records. If non-NULL, set to 1 if any NSEC processed,
 *             set to 0 if all NSECs filtered as wildcard NSECs.
 *
 * @return Proof validation status
 * @retval STAT_SECURE NSEC proof valid: name covered by NSEC range and type absent (NODATA) or
 *                     name falls in NSEC gap (NXDOMAIN)
 * @retval 0 Proof failed: no NSEC covers name, type is present in NSEC bitmap (NODATA failure),
 *           packet parse error, or name extraction failure
 *
 * @note NSEC ordering: uses canonical DNS name comparison (case-insensitive) per RFC 4034 Section 6.1.
 * @note NSEC type bitmap: validates bit for queried type is clear (type absent). Bitmap format per
 *       RFC 4034 Section 4.1.2 with window blocks.
 * @note Wildcard handling: If RRSIG labels < actual name labels, NSEC came from wildcard expansion.
 *       Proof uses wildcard name (e.g., "*.example.com") not expanded name. Per RFC 4035 Section 5.3.2.
 * @note CNAME handling: If NSEC owner equals query name, checks for CNAME bit set. If set, this is
 *       NODATA-at-CNAME case (query type not present but CNAME exists).
 * @note Compares canonicalized names (lowercase) for DNSSEC ordering per RFC 4034 Section 6.1.
 * @note Empty non-terminals: NSEC might cover name but name is empty non-terminal (no RRsets at name,
 *       but subdomains exist). Type bitmap would be empty except for NSEC/RRSIG.
 *
 * @warning Returns 0 on any packet parse error (extract_name failure, short RDATA).
 * @warning Assumes nsecs array valid, all pointers within packet bounds (caller's responsibility).
 * @warning Type bitmap parsing expects RFC 4034 format with window blocks. Malformed bitmap causes
 *          false validation failure.
 * @warning Not thread-safe: uses workspace1_in and workspace2 buffers. Must not be called concurrently
 *          with same buffers.
 *
 * @see prove_non_existence() which calls this function for NSEC proofs
 * @see prove_non_existence_nsec3() for NSEC3-based proof (alternative denial method)
 * @see hostname_cmp() used for canonicalized name comparison
 * @see RFC 4034 Section 4 for NSEC format and Section 6 for canonical ordering
 * @see RFC 4035 Section 5.4 for authenticated denial of existence
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *nsecs[10];
 * unsigned char *labels[10];
 * int nsec_count = 5;
 * char workspace1[MAXDNAME], workspace2[MAXDNAME];
 * char name[MAXDNAME] = "nonexistent.example.com";
 * int nons;
 * int result = prove_non_existence_nsec(header, plen, nsecs, labels, nsec_count,
 *                                       workspace1, workspace2, name, T_A, &nons);
 * if (result == STAT_SECURE) {
 *     // NSEC proof valid
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4034 Section 4 NSEC format and Section 6 canonical ordering.
 * RFC 4035 Section 5.4 authenticated denial of existence. RFC 4035 Section 5.3.2 wildcard handling.
 *
 * SIDE EFFECTS:
 * - Extracts names from packet using extract_name(), advances pointers through packet
 * - Writes NSEC owner name to workspace1_in, NSEC next name to workspace2
 * - Modifies workspace1_in in wildcard detection (prepends "*.")
 * - Sets *nons if non-NULL (0 if all NSECs wildcard-derived, 1 otherwise)
 * - Calls hostname_cmp() for name ordering comparison
 * - Reads NSEC type bitmap from packet
 *
 * THREAD SAFETY: NOT thread-safe. Uses caller-provided workspace buffers. Not reentrant with same
 * buffer arguments.
 */
static int prove_non_existence_nsec(struct dns_header *header, size_t plen, unsigned char **nsecs, unsigned char **labels, int nsec_count,
				    char *workspace1_in, char *workspace2, char *name, int type, int *nons)
{
  int i, rc, rdlen;
  unsigned char *p, *psave;
  int offset = (type & 0xff) >> 3;
  int mask = 0x80 >> (type & 0x07);

  if (nons)
    *nons = 1;
  
  /* Find NSEC record that proves name doesn't exist */
  for (i = 0; i < nsec_count; i++)
    {
      char *workspace1 = workspace1_in;
      int sig_labels, name_labels;

      p = nsecs[i];
      if (!extract_name(header, plen, &p, workspace1, 1, 10))
	return 0;
      p += 8; /* class, type, TTL */
      GETSHORT(rdlen, p);
      psave = p;
      if (!extract_name(header, plen, &p, workspace2, 1, 10))
	return 0;

      /* If NSEC comes from wildcard expansion, use original wildcard
	 as name for computation. */
      sig_labels = *labels[i];
      name_labels = count_labels(workspace1);

      if (sig_labels < name_labels)
	{
	  int k;
	  for (k = name_labels - sig_labels; k != 0; k--)
	    {
	      while (*workspace1 != '.' && *workspace1 != 0)
		workspace1++;
	      if (k != 1 && *workspace1 == '.')
		workspace1++;
	    }
	  
	  workspace1--;
	  *workspace1 = '*';
	}
	  
      rc = hostname_cmp(workspace1, name);
      
      if (rc == 0)
	{
	  /* 4035 para 5.4. Last sentence */
	  if (type == T_NSEC || type == T_RRSIG)
	    return 1;

	  /* NSEC with the same name as the RR we're testing, check
	     that the type in question doesn't appear in the type map */
	  rdlen -= p - psave;
	  /* rdlen is now length of type map, and p points to it */
	  
	  /* If we can prove that there's no NS record, return that information. */
	  if (nons && rdlen >= 2 && p[0] == 0 && (p[2] & (0x80 >> T_NS)) != 0)
	    *nons = 0;
	  
	  if (rdlen >= 2 && p[0] == 0)
	    {
	      /* A CNAME answer would also be valid, so if there's a CNAME is should 
		 have been returned. */
	      if ((p[2] & (0x80 >> T_CNAME)) != 0)
		return 0;
	      
	      /* If the SOA bit is set for a DS record, then we have the
		 DS from the wrong side of the delegation. For the root DS, 
		 this is expected. */
	      if (name_labels != 0 && type == T_DS && (p[2] & (0x80 >> T_SOA)) != 0)
		return 0;
	    }

	  while (rdlen >= 2)
	    {
	      if (!CHECK_LEN(header, p, plen, rdlen))
		return 0;
	      
	      if (p[0] == type >> 8)
		{
		  /* Does the NSEC say our type exists? */
		  if (offset < p[1] && (p[offset+2] & mask) != 0)
		    return 0;
		  
		  break; /* finished checking */
		}
	      
	      rdlen -= p[1];
	      p +=  p[1];
	    }
	  
	  return 1;
	}
      else if (rc == -1)
	{
	  /* Normal case, name falls between NSEC name and next domain name,
	     wrap around case, name falls between NSEC name (rc == -1) and end */
	  if (hostname_cmp(workspace2, name) >= 0 || hostname_cmp(workspace1, workspace2) >= 0)
	    return 1;
	}
      else 
	{
	  /* wrap around case, name falls between start and next domain name */
	  if (hostname_cmp(workspace1, workspace2) >= 0 && hostname_cmp(workspace2, name) >=0 )
	    return 1;
	}
    }
  
  return 0;
}

/* return digest length, or zero on error */
/**
 * @brief Compute NSEC3 hash of domain name per RFC 5155
 *
 * @detailed
 * Computes iterative salted hash of domain name for NSEC3 proofs per RFC 5155 Section 5. Converts
 * domain name to wire format (canonicalized, length-prefixed labels), applies specified hash function
 * (typically SHA-1) with salt, then iterates hash function specified number of times. Each iteration
 * hashes previous digest concatenated with salt. Result is raw hash digest used in NSEC3 owner name
 * matching. Converts input name to wire format (modifies in), computes hash, restores name to
 * presentation format. Uses hash_init() from crypto.c to initialize nettle hash context. Returns
 * digest via *out parameter (caller doesn't free, points to hash_init allocated buffer).
 *
 * @param in Domain name to hash, presentation format. MODIFIED: temporarily converted to wire format
 *           via to_wire(), restored via from_wire() before return.
 * @param out Output parameter for hash digest pointer. Set to point to hash digest buffer allocated
 *            by hash_init(). Caller MUST NOT free buffer. Valid until next hash operation.
 * @param hash Nettle hash algorithm descriptor (e.g., &nettle_sha1 for NSEC3 SHA-1). Defines
 *             hash->update(), hash->digest(), hash->digest_size.
 * @param salt Salt bytes for NSEC3 hashing per RFC 5155 Section 5. Can be NULL if salt_len is 0.
 * @param salt_len Length of salt in bytes. Typically 0-64 bytes. 0 means no salt.
 * @param iterations Number of additional hash iterations per RFC 5155 Section 5. 0 means one hash
 *                   (initial), 1 means initial + 1 additional = 2 total hashes. Typical values 0-150.
 *
 * @return Hash digest size in bytes (typically 20 for SHA-1)
 * @retval >0 Success, digest size (hash->digest_size)
 * @retval 0 Failure: hash_init() failed (memory allocation failure)
 *
 * @note Hash algorithm: RFC 5155 defines SHA-1 (algorithm 1) as mandatory. Future RFCs may add more.
 * @note Iteration count: Higher iterations increase CPU cost for attackers but also for validators.
 *       RFC 5155 recommends implementation-dependent limits (e.g., max 150 iterations).
 * @note Salt: Optional per RFC 5155. Salt prevents pre-computed hash tables. Salt changes require
 *            re-signing NSEC3 records in zone.
 * @note Wire format conversion: to_wire() modifies in temporarily, from_wire() restores it.
 * @note Digest buffer: Managed by hash_init() in crypto.c. Not freed by caller. Static or module-local
 *       storage in crypto.c.
 * @note Hash format: Hash(Hash(...Hash(Hash(name || salt) || salt)...)) per RFC 5155 Section 5.
 *
 * @warning in parameter MODIFIED temporarily (converted to wire format, then restored). Not const.
 * @warning Returns 0 if hash_init() fails (memory allocation failure). Caller must check return value.
 * @warning *out points to static/module-local buffer in crypto.c. Not thread-safe if multiple hash
 *          operations concurrent.
 * @warning Iteration count unbounded in code. Excessive iterations (>1000) can cause CPU exhaustion
 *          DoS. Caller should enforce iteration limit before calling.
 * @warning Not reentrant: uses hash context from hash_init(). Concurrent calls corrupt state.
 *
 * @see check_nsec3_coverage() which calls hash_name() to compute query name hash for NSEC3 matching
 * @see prove_non_existence_nsec3() which uses hash_name() for NSEC3 proofs
 * @see hash_init() in crypto.c for hash context initialization
 * @see to_wire() for name canonicalization (wire format conversion)
 * @see from_wire() for wire format to presentation format restoration
 * @see RFC 5155 Section 5 for NSEC3 hash computation algorithm
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME] = "www.example.com";
 * unsigned char *digest;
 * unsigned char salt[] = {0x12, 0x34};
 * int digest_len = hash_name(name, &digest, &nettle_sha1, salt, 2, 10);
 * if (digest_len > 0) {
 *     // Use digest for NSEC3 owner name comparison
 * }
 * // name is restored to presentation format
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 5155 Section 5 NSEC3 hash computation. Supports arbitrary iteration
 * count and salt length per RFC 5155.
 *
 * SIDE EFFECTS:
 * - Converts in to wire format via to_wire() (modifies in temporarily)
 * - Initializes hash context via hash_init() (allocates digest buffer)
 * - Calls hash->update() multiple times (1 + iterations iterations total)
 * - Calls hash->digest() to finalize each iteration
 * - Restores in to presentation format via from_wire()
 * - Sets *out to point to digest buffer
 *
 * THREAD SAFETY: NOT thread-safe. Modifies in temporarily. Uses hash context from hash_init() which
 * may use static storage. Not reentrant.
 */
static int hash_name(char *in, unsigned char **out, struct nettle_hash const *hash, 
		     unsigned char *salt, int salt_len, int iterations)
{
  void *ctx;
  unsigned char *digest;
  int i;

  if (!hash_init(hash, &ctx, &digest))
    return 0;
 
  hash->update(ctx, to_wire(in), (unsigned char *)in);
  hash->update(ctx, salt_len, salt);
  hash->digest(ctx, hash->digest_size, digest);

  for(i = 0; i < iterations; i++)
    {
      hash->update(ctx, hash->digest_size, digest);
      hash->update(ctx, salt_len, salt);
      hash->digest(ctx, hash->digest_size, digest);
    }
   
  from_wire(in);

  *out = digest;
  return hash->digest_size;
}

/**
 * @brief Decode base32-encoded NSEC3 owner name hash per RFC 4648
 *
 * @detailed
 * Decodes base32-encoded hash from NSEC3 owner name first label to binary digest for hash comparison
 * per RFC 4648 (base32 alphabet) and RFC 5155 Section 3.2 (NSEC3 owner name format). NSEC3 owner
 * names have format "<base32-hash>.<zone>", e.g., "0P9MHAVEQVM6T7VVJ... .example.com". This function
 * decodes the first label (up to first '.' or end of string) from base32 ASCII to binary hash bytes.
 * Uses RFC 4648 base32 alphabet: A-Z (values 0-25) and 2-7 (values 26-31), case-insensitive. Pads
 * with '=' ignored. Processes 8 base32 characters (40 bits) to produce 5 output bytes. Handles partial
 * last group. Returns decoded byte count. Used by check_nsec3_coverage() to decode NSEC3 owner and
 * next hashes for comparison with computed query hash.
 *
 * @param in Input base32-encoded string (NSEC3 owner name first label). Typically 26-32 characters
 *           for SHA-1 (20 bytes = 32 base32 chars). Decoding stops at first '.' or null terminator.
 *           Modified: characters uppercased in place during decoding.
 * @param out Output buffer for decoded binary bytes. Must be at least ceil(len(in) * 5 / 8) bytes.
 *            For 32-char base32 input (160 bits), outputs 20 bytes. Caller allocates.
 *
 * @return Number of decoded bytes written to out
 * @retval >0 Success, decoded byte count (typically 20 for SHA-1 NSEC3 hashes)
 * @retval 0 if input is empty (no characters before '.' or end)
 *
 * @note Base32 alphabet: A-Z maps to 0-25, 2-7 maps to 26-31 per RFC 4648 Section 6.
 * @note Case-insensitive: Uppercase and lowercase letters both accepted. Function uppercases input.
 * @note Padding '=' ignored: Not required for decoding, function skips if present.
 * @note Stops at '.': Decodes only first label of NSEC3 owner name (hash part).
 * @note Decoding groups: 8 base32 chars (40 bits) → 5 bytes. Partial groups handled (e.g., 4 chars
 *       → 2.5 bytes rounded down to 2 bytes).
 * @note Invalid characters: If character not A-Z, 2-7, '.', or '=', treated as alphabet index 0
 *       (character 'A'). No error returned for invalid base32.
 * @note NSEC3 owner format: Per RFC 5155 Section 3.2, NSEC3 owner is "<hash>.<zone>" where <hash>
 *       is base32-encoded hash with no padding (RFC 5155 uses modified base32hex, but dnsmasq uses
 *       standard base32 per RFC 4648).
 *
 * @warning in parameter MODIFIED: characters uppercased in place. Not const.
 * @warning No buffer overflow check on out. Caller must ensure out buffer large enough (at least
 *          ceil(strlen(in) * 5 / 8) bytes).
 * @warning Invalid base32 characters silently treated as 'A' (value 0). No error detection.
 * @warning No padding validation: If '=' present, simply skipped. Malformed padding accepted.
 * @warning Returns 0 on empty input (string starts with '.' or null). Caller must check.
 *
 * @see check_nsec3_coverage() which calls base32_decode() to decode NSEC3 owner and next hashes
 * @see hash_name() which computes hash that base32_decode() reverses
 * @see RFC 4648 Section 6 for base32 encoding alphabet
 * @see RFC 5155 Section 3.2 for NSEC3 owner name format
 *
 * EXAMPLE USAGE:
 * @code
 * char owner[MAXDNAME] = "0P9MHAVEQVM6T7VVJFLI2GO8OAN028RT.example.com";
 * unsigned char hash[32]; // SHA-1 = 20 bytes typically
 * int hash_len = base32_decode(owner, hash); // Decodes first label
 * if (hash_len > 0) {
 *     // Compare hash with computed query hash
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4648 Section 6 base32 decoding for RFC 5155 Section 3.2 NSEC3
 * owner name hash labels.
 *
 * SIDE EFFECTS:
 * - Modifies in: uppercases characters in place during decoding
 * - Writes decoded bytes to out (hash_len bytes)
 * - No memory allocation
 *
 * THREAD SAFETY: NOT thread-safe. Modifies in parameter. Can be called concurrently with different
 * buffers.
 */
static int base32_decode(char *in, unsigned char *out)
{
  int oc, on, c, mask, i;
  unsigned char *p = out;
 
  for (c = *in, oc = 0, on = 0; c != 0 && c != '.'; c = *++in) 
    {
      if (c >= '0' && c <= '9')
	c -= '0';
      else if (c >= 'a' && c <= 'v')
	c -= 'a', c += 10;
      else if (c >= 'A' && c <= 'V')
	c -= 'A', c += 10;
      else
	return 0;
      
      for (mask = 0x10, i = 0; i < 5; i++)
        {
	  if (c & mask)
	    oc |= 1;
	  mask = mask >> 1;
	  if (((++on) & 7) == 0)
	    *p++ = oc;
	  oc = oc << 1;
	}
    }
  
  if ((on & 7) != 0)
    return 0;

  return p - out;
}

/**
 * @brief Check if NSEC3 records cover query name hash for denial-of-existence proof
 *
 * @detailed
 * Validates NSEC3-based denial-of-existence proof by checking if any NSEC3 record's hash range covers
 * the computed query name hash per RFC 5155 Section 7.2. Decodes base32-encoded NSEC3 owner name hash
 * and next hash, compares with computed digest to determine if digest falls in range [owner, next).
 * NSEC3 uses cyclical hash ordering (wraps at zone apex), so handles wrap-around case where next < owner.
 * For NODATA proof, also checks that queried type is absent in NSEC3 type bitmap. For NXDOMAIN, validates
 * name doesn't exist (hash covered) and closest encloser exists. Handles opt-out flag (RFC 5155 Section
 * 6) where unsigned delegations are not covered. Returns STAT_SECURE if proof valid, 0 if proof fails
 * or incomplete.
 *
 * @param header DNS packet header containing response with NSEC3 records
 * @param plen Packet length in bytes for bounds checking
 * @param digest_len Length of computed query name hash digest in bytes (typically 20 for SHA-1)
 * @param digest Computed query name hash from hash_name(), binary format. Compared against NSEC3
 *               owner and next hashes to find covering NSEC3.
 * @param type Query type for NODATA proof (e.g., T_A, T_AAAA). Checked against NSEC3 type bitmap.
 *             For NXDOMAIN proof, type presence doesn't matter.
 * @param workspace1 Temporary buffer for NSEC3 owner name extraction (MAXDNAME size)
 * @param workspace2 Temporary buffer for base32-decoded hash bytes (must be at least digest_len bytes)
 * @param nsecs Array of pointers to NSEC3 record start positions in packet. Each pointer points to
 *              NSEC3 owner name. NULL entries skipped.
 * @param nsec_count Number of NSEC3 records in nsecs array
 * @param nons Optional output flag for matching NSEC3 presence. If non-NULL, set to 0 if matching
 *             NSEC3 is opt-out (unsigned delegation), set to 1 if matching NSEC3 is not opt-out.
 * @param name_labels Number of labels in query name. Used for closest encloser calculation in
 *                    NXDOMAIN proofs. Compared against NSEC3 owner labels to determine if query name
 *                    or ancestor matched.
 *
 * @return Proof validation status
 * @retval STAT_SECURE NSEC3 proof valid: digest covered by NSEC3 range and type absent (NODATA) or
 *                     name doesn't exist (NXDOMAIN)
 * @retval 0 Proof failed: no NSEC3 covers digest, type present in NSEC3 bitmap (NODATA failure),
 *           opt-out NSEC3 for insecure delegation, packet parse error, or base32 decode failure
 *
 * @note Hash ordering: NSEC3 uses cyclical ordering. If next < owner, range is [owner, zone_max] ∪
 *       [zone_min, next). Handles wrap-around at zone apex.
 * @note Opt-out flag: RFC 5155 Section 6 allows unsigned delegations in opt-out zones. If NSEC3 flags
 *       bit 0 set (opt-out), and query is for delegation (NS type or ancestor of query), proof fails
 *       (insecure delegation). Sets *nons to 0.
 * @note Type bitmap: NSEC3 type bitmap format identical to NSEC per RFC 4034 Section 4.1.2. Validates
 *       queried type bit is clear in bitmap.
 * @note Closest encloser: For NXDOMAIN, requires closest encloser (longest existing ancestor) proven.
 *       If NSEC3 owner labels < query labels and type not DS, this NSEC3 covers wildcard at closest
 *       encloser (required per RFC 5155 Section 7.2.2).
 * @note Hash comparison: Binary comparison of decoded hashes, not base32 string comparison. More
 *       efficient.
 * @note NULL entries in nsecs: Skipped (NULL indicates filtered-out NSEC3, e.g., wrong parameters).
 *
 * @warning Returns 0 on extract_name() failure (packet parse error).
 * @warning Returns 0 on base32_decode() failure (malformed NSEC3 owner name).
 * @warning Returns 0 if digest_len, base32_len, or hash_len mismatch (inconsistent hash sizes).
 * @warning Returns 0 on CHECK_LEN() failure (short RDATA, packet truncation).
 * @warning Assumes nsecs array valid, non-NULL entries point to valid NSEC3 records.
 * @warning Type bitmap parsing expects RFC 4034 format. Malformed bitmap causes false failure.
 * @warning Not thread-safe: uses workspace1 and workspace2 buffers. Must not be called concurrently
 *          with same buffers.
 *
 * @see prove_non_existence_nsec3() which calls check_nsec3_coverage() for NSEC3 proof validation
 * @see hash_name() which computes digest parameter
 * @see base32_decode() used to decode NSEC3 owner and next hashes
 * @see RFC 5155 Section 7.2 for NSEC3 denial-of-existence proof algorithm
 * @see RFC 5155 Section 6 for opt-out flag semantics
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *nsecs[10];
 * int nsec_count = 5;
 * unsigned char digest[20]; // SHA-1 hash
 * int digest_len = 20;
 * char workspace1[MAXDNAME], workspace2[MAXDNAME];
 * int nons, name_labels = count_labels("www.example.com");
 * int result = check_nsec3_coverage(header, plen, digest_len, digest, T_A,
 *                                   workspace1, workspace2, nsecs, nsec_count,
 *                                   &nons, name_labels);
 * if (result == STAT_SECURE) {
 *     // NSEC3 proof valid
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 5155 Section 7.2 NSEC3 matching algorithm. RFC 5155 Section 6
 * opt-out flag handling. RFC 4034 Section 4.1.2 type bitmap format.
 *
 * SIDE EFFECTS:
 * - Extracts NSEC3 owner name from packet via extract_name(), writes to workspace1
 * - Decodes base32 NSEC3 owner hash via base32_decode(), writes to workspace2
 * - Parses NSEC3 RDATA (hash algorithm, flags, iterations, salt, hash length, next hash)
 * - Reads NSEC3 type bitmap from packet
 * - Sets *nons if non-NULL (0 for opt-out match, 1 for non-opt-out match)
 * - Calls count_labels() on NSEC3 owner name
 *
 * THREAD SAFETY: NOT thread-safe. Uses workspace1 and workspace2 buffers. Not reentrant with same
 * buffer arguments.
 */
static int check_nsec3_coverage(struct dns_header *header, size_t plen, int digest_len, unsigned char *digest, int type,
				char *workspace1, char *workspace2, unsigned char **nsecs, int nsec_count, int *nons, int name_labels)
{
  int i, hash_len, salt_len, base32_len, rdlen, flags;
  unsigned char *p, *psave;

  for (i = 0; i < nsec_count; i++)
    if ((p = nsecs[i]))
      {
       	if (!extract_name(header, plen, &p, workspace1, 1, 0) ||
	    !(base32_len = base32_decode(workspace1, (unsigned char *)workspace2)))
	  return 0;
	
	p += 8; /* class, type, TTL */
	GETSHORT(rdlen, p);
	psave = p;
	p++; /* algo */
	flags = *p++; /* flags */
	p += 2; /* iterations */
	salt_len = *p++; /* salt_len */
	p += salt_len; /* salt */
	hash_len = *p++; /* p now points to next hashed name */
	
	if (!CHECK_LEN(header, p, plen, hash_len))
	  return 0;
	
	if (digest_len == base32_len && hash_len == base32_len)
	  {
	    int rc = memcmp(workspace2, digest, digest_len);

	    if (rc == 0)
	      {
		/* We found an NSEC3 whose hashed name exactly matches the query, so
		   we just need to check the type map. p points to the RR data for the record. */
		
		int offset = (type & 0xff) >> 3;
		int mask = 0x80 >> (type & 0x07);
		
		p += hash_len; /* skip next-domain hash */
		rdlen -= p - psave;

		if (!CHECK_LEN(header, p, plen, rdlen))
		  return 0;
		
		if (rdlen >= 2 && p[0] == 0)
		  {
		    /* If we can prove that there's no NS record, return that information. */
		    if (nons && (p[2] & (0x80 >> T_NS)) != 0)
		      *nons = 0;
		
		    /* A CNAME answer would also be valid, so if there's a CNAME is should 
		       have been returned. */
		    if ((p[2] & (0x80 >> T_CNAME)) != 0)
		      return 0;
		    
		    /* If the SOA bit is set for a DS record, then we have the
		       DS from the wrong side of the delegation. For the root DS, 
		       this is expected.  */
		    if (name_labels != 0 && type == T_DS && (p[2] & (0x80 >> T_SOA)) != 0)
		      return 0;
		  }

		while (rdlen >= 2)
		  {
		    if (p[0] == type >> 8)
		      {
			/* Does the NSEC3 say our type exists? */
			if (offset < p[1] && (p[offset+2] & mask) != 0)
			  return 0;
			
			break; /* finished checking */
		      }
		    
		    rdlen -= p[1];
		    p +=  p[1];
		  }
		
		return 1;
	      }
	    else if (rc < 0)
	      {
		/* Normal case, hash falls between NSEC3 name-hash and next domain name-hash,
		   wrap around case, name-hash falls between NSEC3 name-hash and end */
		if (memcmp(p, digest, digest_len) >= 0 || memcmp(workspace2, p, digest_len) >= 0)
		  {
		    if ((flags & 0x01) && nons) /* opt out */
		      *nons = 0;

		    return 1;
		  }
	      }
	    else 
	      {
		/* wrap around case, name falls between start and next domain name */
		if (memcmp(workspace2, p, digest_len) >= 0 && memcmp(p, digest, digest_len) >= 0)
		  {
		    if ((flags & 0x01) && nons) /* opt out */
		      *nons = 0;

		    return 1;
		  }
	      }
	  }
      }

  return 0;
}

/**
 * @brief Validate NSEC3 denial-of-existence proof per RFC 5155
 *
 * @detailed
 * Validates NSEC3-based authenticated denial of existence for negative answers (NXDOMAIN or NODATA)
 * per RFC 5155 Section 7.2. Implements complete NSEC3 proof algorithm: extracts hash algorithm,
 * iterations, and salt from first usable NSEC3 record, prunes NSEC3s with different parameters,
 * computes hashes of query name and potential wildcards (closest encloser, next closest, wildcard
 * at closest encloser), checks if computed hashes are covered by NSEC3 ranges. For NXDOMAIN, requires
 * three NSEC3 proofs: (1) closest encloser exists, (2) next closest doesn't exist, (3) no wildcard
 * at closest encloser. For NODATA, requires one NSEC3 covering query name with type absent or wildcard
 * proof. Handles opt-out zones (RFC 5155 Section 6) for unsigned delegations. Returns STAT_SECURE if
 * proof valid, 0 if proof incomplete or fails.
 *
 * @param header DNS packet header containing response with NSEC3 records
 * @param plen Packet length in bytes for bounds checking
 * @param nsecs Array of pointers to NSEC3 record start positions in packet. Each pointer points to
 *              NSEC3 owner name. Records with different hash parameters pruned during processing.
 * @param nsec_count Number of NSEC3 records in nsecs array
 * @param workspace1 Temporary buffer for name processing (MAXDNAME size)
 * @param workspace2 Temporary buffer for hash computation (MAXDNAME size)
 * @param name Query name to prove non-existence, presentation format (e.g., "www.example.com")
 * @param type Query type for NODATA proof (e.g., T_A, T_AAAA). For NXDOMAIN, type is irrelevant.
 * @param wildname Optional output buffer for wildcard source name if wildcard expansion detected.
 *                 If non-NULL and wildcard match found, set to wildcard at closest encloser
 *                 (e.g., "*.example.com").
 * @param nons Optional output flag for opt-out handling. If non-NULL, set to 0 if proof relies on
 *             opt-out NSEC3 (insecure delegation), set to 1 if proof does not use opt-out.
 *
 * @return Proof validation status
 * @retval STAT_SECURE NSEC3 proof valid: NXDOMAIN or NODATA proven with complete NSEC3 coverage
 * @retval 0 Proof failed: no usable NSEC3 (unknown hash algorithm), hash computation failed,
 *           required NSEC3 coverage missing, type present in NSEC3 bitmap (NODATA failure), or
 *           packet parse error
 *
 * @note Hash algorithm selection: Uses first NSEC3 with supported hash algorithm (SHA-1 = 1). Prunes
 *       NSEC3s with different algorithm, iterations, or salt. All NSEC3s in proof must have identical
 *       parameters per RFC 5155 Section 7.2.
 * @note NXDOMAIN proof: Requires three NSEC3 records: (1) closest encloser hash covered (proves closest
 *       encloser exists), (2) next closest hash covered (proves next closest doesn't exist), (3) wildcard
 *       at closest encloser hash covered (proves no wildcard expansion). Per RFC 5155 Section 7.2.2.
 * @note NODATA proof: Requires NSEC3 covering query name hash with type absent in bitmap, or NSEC3
 *       covering wildcard at closest encloser with type absent. Per RFC 5155 Section 7.2.4.
 * @note Closest encloser: Longest existing ancestor of query name. Computed by stripping labels until
 *       hash matches NSEC3 owner. E.g., for "www.a.example.com", might be "example.com".
 * @note Next closest: Label immediately below closest encloser. E.g., if closest encloser is "example.com"
 *       and query is "www.a.example.com", next closest is "a.example.com".
 * @note Wildcard at closest encloser: "*.closest_encloser". E.g., if closest encloser is "example.com",
 *       wildcard is "*.example.com".
 * @note Opt-out: RFC 5155 Section 6 allows unsigned delegations in opt-out zones. If check_nsec3_coverage()
 *       returns opt-out match, validation fails (insecure delegation). Sets *nons to 0.
 * @note Parameter pruning: NULLs out nsecs[i] entries with different hash algorithm, iterations, or
 *       salt than selected parameters. check_nsec3_coverage() skips NULL entries.
 *
 * @warning Returns 0 if no NSEC3 with supported hash algorithm (e.g., all SHA-256, but only SHA-1
 *          supported).
 * @warning Returns 0 on hash_name() failure (memory allocation in hash_init()).
 * @warning Returns 0 on packet parse error (skip_name(), extract_name() failures).
 * @warning Returns 0 if base32_decode() fails on any NSEC3 owner name.
 * @warning Assumes nsecs array valid, all pointers within packet bounds initially.
 * @warning Not thread-safe: uses workspace1 and workspace2 buffers, calls non-reentrant functions
 *          (hash_name()). Must not be called concurrently with same buffers.
 * @warning Modifies nsecs array: NULLs out entries with different hash parameters.
 *
 * @see prove_non_existence() which calls this function for NSEC3 proofs
 * @see check_nsec3_coverage() called for each hash to find covering NSEC3
 * @see hash_name() used to compute name hashes
 * @see base32_decode() used to decode NSEC3 owner hashes
 * @see RFC 5155 Section 7.2 for NSEC3 proof algorithm
 * @see RFC 5155 Section 7.2.2 for NXDOMAIN proof requirements
 * @see RFC 5155 Section 7.2.4 for NODATA proof requirements
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *nsecs[10];
 * int nsec_count = 6;
 * char workspace1[MAXDNAME], workspace2[MAXDNAME];
 * char name[MAXDNAME] = "nonexistent.example.com";
 * char wildname[MAXDNAME];
 * int nons;
 * int result = prove_non_existence_nsec3(header, plen, nsecs, nsec_count,
 *                                        workspace1, workspace2, name, T_A,
 *                                        wildname, &nons);
 * if (result == STAT_SECURE) {
 *     // NSEC3 proof valid
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 5155 Section 7.2 NSEC3 proof algorithm. RFC 5155 Section 7.2.2
 * NXDOMAIN proof. RFC 5155 Section 7.2.4 NODATA proof. RFC 5155 Section 6 opt-out handling.
 *
 * SIDE EFFECTS:
 * - Extracts hash algorithm, iterations, salt from first usable NSEC3 via skip_name(), extract_name()
 * - Prunes nsecs array: NULLs out entries with different hash parameters
 * - Computes hashes via hash_name() for query name, closest encloser, next closest, wildcard
 * - Calls check_nsec3_coverage() up to 3 times for NXDOMAIN proof
 * - Writes to workspace1 and workspace2 repeatedly during hash computation and NSEC3 parsing
 * - Sets *wildname if non-NULL and wildcard detected
 * - Sets *nons if non-NULL (0 for opt-out, 1 otherwise)
 *
 * THREAD SAFETY: NOT thread-safe. Uses workspace buffers, calls non-reentrant hash_name(). Modifies
 * nsecs array. Not reentrant.
 */
static int prove_non_existence_nsec3(struct dns_header *header, size_t plen, unsigned char **nsecs, int nsec_count,
				     char *workspace1, char *workspace2, char *name, int type, char *wildname, int *nons)
{
  unsigned char *salt, *p, *digest;
  int digest_len, i, iterations, salt_len, base32_len, algo = 0;
  struct nettle_hash const *hash;
  char *closest_encloser, *next_closest, *wildcard;
  
  if (nons)
    *nons = 1;
  
  /* Look though the NSEC3 records to find the first one with 
     an algorithm we support.

     Take the algo, iterations, and salt of that record
     as the ones we're going to use, and prune any 
     that don't match. */
  
  for (i = 0; i < nsec_count; i++)
    {
      if (!(p = skip_name(nsecs[i], header, plen, 15)))
	return 0; /* bad packet */
      
     p += 10; /* type, class, TTL, rdlen */
      algo = *p++;
      
      if ((hash = hash_find(nsec3_digest_name(algo))))
	break; /* known algo */
    }

  /* No usable NSEC3s */
  if (i == nsec_count)
    return 0;

  p++; /* flags */

  GETSHORT (iterations, p);
  /* Upper-bound iterations, to avoid DoS.
     Strictly, there are lower bounds for small keys, but
     since we don't have key size info here, at least limit
     to the largest bound, for 4096-bit keys. RFC 5155 10.3 */
  if (iterations > 2500)
    return 0;
  
  salt_len = *p++;
  salt = p;
  if (!CHECK_LEN(header, salt, plen, salt_len))
    return 0; /* bad packet */
    
  /* Now prune so we only have NSEC3 records with same iterations, salt and algo */
  for (i = 0; i < nsec_count; i++)
    {
      unsigned char *nsec3p = nsecs[i];
      int this_iter, flags;

      nsecs[i] = NULL; /* Speculative, will be restored if OK. */
      
      if (!(p = skip_name(nsec3p, header, plen, 15)))
	return 0; /* bad packet */
      
      p += 10; /* type, class, TTL, rdlen */
      
      if (*p++ != algo)
	continue;
 
      flags = *p++; /* flags */
      
      /* 5155 8.2 */
      if (flags != 0 && flags != 1)
	continue;

      GETSHORT(this_iter, p);
      if (this_iter != iterations)
	continue;

      if (salt_len != *p++)
	continue;
      
      if (!CHECK_LEN(header, p, plen, salt_len))
	return 0; /* bad packet */

      if (memcmp(p, salt, salt_len) != 0)
	continue;

      /* All match, put the pointer back */
      nsecs[i] = nsec3p;
    }

  if ((digest_len = hash_name(name, &digest, hash, salt, salt_len, iterations)) == 0)
    return 0;
  
  if (check_nsec3_coverage(header, plen, digest_len, digest, type, workspace1, workspace2, nsecs, nsec_count, nons, count_labels(name)))
    return 1;

  /* Can't find an NSEC3 which covers the name directly, we need the "closest encloser NSEC3" 
     or an answer inferred from a wildcard record. */
  closest_encloser = name;
  next_closest = NULL;

  do
    {
      if (*closest_encloser == '.')
	closest_encloser++;

      if (wildname && hostname_isequal(closest_encloser, wildname))
	break;

      if ((digest_len = hash_name(closest_encloser, &digest, hash, salt, salt_len, iterations)) == 0)
	return 0;
      
      for (i = 0; i < nsec_count; i++)
	if ((p = nsecs[i]))
	  {
	    if (!extract_name(header, plen, &p, workspace1, 1, 0) ||
		!(base32_len = base32_decode(workspace1, (unsigned char *)workspace2)))
	      return 0;
	  
	    if (digest_len == base32_len &&
		memcmp(digest, workspace2, digest_len) == 0)
	      break; /* Gotit */
	  }
      
      if (i != nsec_count)
	break;
      
      next_closest = closest_encloser;
    }
  while ((closest_encloser = strchr(closest_encloser, '.')));
  
  if (!closest_encloser || !next_closest)
    return 0;
  
  /* Look for NSEC3 that proves the non-existence of the next-closest encloser */
  if ((digest_len = hash_name(next_closest, &digest, hash, salt, salt_len, iterations)) == 0)
    return 0;

  if (!check_nsec3_coverage(header, plen, digest_len, digest, type, workspace1, workspace2, nsecs, nsec_count, NULL, 1))
    return 0;
  
  /* Finally, check that there's no seat of wildcard synthesis */
  if (!wildname)
    {
      if (!(wildcard = strchr(next_closest, '.')) || wildcard == next_closest)
	return 0;
      
      wildcard--;
      *wildcard = '*';
      
      if ((digest_len = hash_name(wildcard, &digest, hash, salt, salt_len, iterations)) == 0)
	return 0;
      
      if (!check_nsec3_coverage(header, plen, digest_len, digest, type, workspace1, workspace2, nsecs, nsec_count, NULL, 1))
	return 0;
    }
  
  return 1;
}

/**
 * @brief Coordinate NSEC/NSEC3 denial-of-existence proof validation for negative answers
 *
 * @detailed
 * Main coordinator function for validating authenticated denial of existence using NSEC or NSEC3
 * records per RFC 4035 Section 5.4 and RFC 5155. Scans authority section for NSEC or NSEC3 records
 * (no mixing allowed), extracts corresponding RRSIG labels for wildcard detection, and delegates to
 * prove_non_existence_nsec() or prove_non_existence_nsec3() for actual proof validation. Handles
 * both NXDOMAIN (name does not exist) and NODATA (name exists but no records of queried type) proofs.
 * Detects wildcard expansion by comparing RRSIG labels field to actual name labels. Computes TTL
 * floor from NSEC/NSEC3 and their RRSIGs for negative caching. Returns failure if NSEC and NSEC3
 * are mixed (security violation).
 *
 * @param header DNS packet header containing negative answer with authority section NSEC/NSEC3 records
 * @param plen Packet length in bytes for bounds checking
 * @param keyname DNSKEY signer name from RRSIGs, used for zone determination in proofs
 * @param name Query name that allegedly doesn't exist or has no data, presentation format
 * @param qtype Query type for NODATA proof validation (e.g., T_A, T_AAAA)
 * @param qclass Query class (e.g., C_IN)
 * @param wildname Optional output buffer for wildcard source name if wildcard expansion detected.
 *                 If non-NULL and wildcard detected, points to wildcard name (e.g., "*.example.com").
 * @param nons Optional output flag for authority section presence. If non-NULL, set to 1 if any
 *             NSEC/NSEC3 found in authority section.
 * @param nsec_ttl Optional output for minimum TTL from NSEC/NSEC3 and RRSIGs, used for negative
 *                 answer caching. Limited by RRSIG original_ttl per RFC 4035 Section 5.3.3.
 *
 * @return Proof validation status
 * @retval STAT_SECURE Denial of existence proof is valid (NSEC/NSEC3 covers queried name/type)
 * @retval 0 Proof failed: no NSEC/NSEC3 found, mixed NSEC/NSEC3, proof doesn't cover name/type,
 *           bad packet format, or memory allocation failure
 *
 * @note Requires exactly NSEC or NSEC3 in authority section, no mixing. Mixed types return 0.
 * @note Extracts RRSIG labels field for wildcard detection per RFC 4035 Section 5.3.2. Multiple
 *       RRSIGs for same NSEC must have same labels value or proof fails.
 * @note TTL computation: min(NSEC/NSEC3 TTL, corresponding RRSIG original_ttl) per RFC 4035
 *       Section 5.3.3.
 * @note Delegates to prove_non_existence_nsec() for NSEC proofs (RFC 4034/4035).
 * @note Delegates to prove_non_existence_nsec3() for NSEC3 proofs (RFC 5155).
 *
 * @warning Mixed NSEC and NSEC3 records in same response considered attack. Returns 0.
 * @warning NSEC without corresponding RRSIG is error. Returns 0.
 * @warning Memory allocation failure (nsecset, rrsig_labels expansion) returns 0.
 * @warning Uses static nsecset and rrsig_labels arrays. Not thread-safe.
 *
 * @see prove_non_existence_nsec() for NSEC proof validation
 * @see prove_non_existence_nsec3() for NSEC3 proof validation
 * @see dnssec_validate_reply() which calls prove_non_existence() for negative answers
 * @see RFC 4035 Section 5.4 for authenticated denial of existence
 * @see RFC 5155 for NSEC3 specification
 *
 * EXAMPLE USAGE:
 * @code
 * char keyname[MAXDNAME] = "example.com";
 * char name[MAXDNAME] = "nonexistent.example.com";
 * char wildname[MAXDNAME];
 * int nons, nsec_ttl;
 * int result = prove_non_existence(header, plen, keyname, name, T_A, C_IN,
 *                                   wildname, &nons, &nsec_ttl);
 * if (result == STAT_SECURE) {
 *     // NXDOMAIN/NODATA proof valid, cache negative answer with nsec_ttl
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4035 Section 5.4 authenticated denial of existence using NSEC or
 * NSEC3. RFC 4035 Section 5.3.2 wildcard expansion detection. RFC 4035 Section 5.3.3 TTL handling.
 *
 * SIDE EFFECTS:
 * - Scans authority section, modifies p pointer through packet
 * - Expands static nsecset array to hold NSEC/NSEC3 pointers
 * - Expands static rrsig_labels array to hold RRSIG labels values
 * - Uses daemon->workspacename for name extraction
 * - Sets *nons if non-NULL
 * - Sets *nsec_ttl if non-NULL (TTL floor from NSEC/NSEC3 and RRSIGs)
 * - Sets *wildname if non-NULL and wildcard detected
 * - Calls prove_non_existence_nsec() or prove_non_existence_nsec3() with side effects
 *
 * THREAD SAFETY: NOT thread-safe. Uses static nsecset and rrsig_labels arrays. Not reentrant.
 */
static int prove_non_existence(struct dns_header *header, size_t plen, char *keyname, char *name, int qtype, int qclass, char *wildname, int *nons, int *nsec_ttl)
{
  static unsigned char **nsecset = NULL, **rrsig_labels = NULL;
  static int nsecset_sz = 0, rrsig_labels_sz = 0;
  
  int type_found = 0;
  unsigned char *auth_start, *p = skip_questions(header, plen);
  int type, class, rdlen, i, nsecs_found;
  unsigned long ttl;
  
  /* Move to NS section */
  if (!p || !(p = skip_section(p, ntohs(header->ancount), header, plen)))
    return 0;

  auth_start = p;
  
  for (nsecs_found = 0, i = 0; i < ntohs(header->nscount); i++)
    {
      unsigned char *pstart = p;
      
      if (!extract_name(header, plen, &p, daemon->workspacename, 1, 10))
	return 0;
	  
      GETSHORT(type, p); 
      GETSHORT(class, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);

      if (class == qclass && (type == T_NSEC || type == T_NSEC3))
	{
	  if (nsec_ttl)
	    {
	      /* Limit TTL with sig TTL */
	      if (daemon->rr_status[ntohs(header->ancount) + i] < ttl)
		ttl = daemon->rr_status[ntohs(header->ancount) + i];
	      *nsec_ttl = ttl;
	    }
	  
	  /* No mixed NSECing 'round here, thankyouverymuch */
	  if (type_found != 0 && type_found != type)
	    return 0;

	  type_found = type;

	  if (!expand_workspace(&nsecset, &nsecset_sz, nsecs_found))
	    return 0; 
	  
	  if (type == T_NSEC)
	    {
	      /* If we're looking for NSECs, find the corresponding SIGs, to 
		 extract the labels value, which we need in case the NSECs
		 are the result of wildcard expansion.
		 Note that the NSEC may not have been validated yet
		 so if there are multiple SIGs, make sure the label value
		 is the same in all, to avoid be duped by a rogue one.
		 If there are no SIGs, that's an error */
	      unsigned char *p1 = auth_start;
	      int res, j, rdlen1, type1, class1;
	      
	      if (!expand_workspace(&rrsig_labels, &rrsig_labels_sz, nsecs_found))
		return 0;
	      
	      rrsig_labels[nsecs_found] = NULL;
	      
	      for (j = ntohs(header->nscount); j != 0; j--)
		{
		  if (!(res = extract_name(header, plen, &p1, daemon->workspacename, 0, 10)))
		    return 0;

		   GETSHORT(type1, p1); 
		   GETSHORT(class1, p1);
		   p1 += 4; /* TTL */
		   GETSHORT(rdlen1, p1);

		   if (!CHECK_LEN(header, p1, plen, rdlen1))
		     return 0;
		   
		   if (res == 1 && class1 == qclass && type1 == T_RRSIG)
		     {
		       int type_covered;
		       unsigned char *psav = p1;
		       
		       if (rdlen1 < 18)
			 return 0; /* bad packet */

		       GETSHORT(type_covered, p1);

		       if (type_covered == T_NSEC)
			 {
			   p1++; /* algo */
			   
			   /* labels field must be the same in every SIG we find. */
			   if (!rrsig_labels[nsecs_found])
			     rrsig_labels[nsecs_found] = p1;
			   else if (*rrsig_labels[nsecs_found] != *p1) /* algo */
			     return 0;
			   }
		       p1 = psav;
		     }
		   
		   if (!ADD_RDLEN(header, p1, plen, rdlen1))
		     return 0;
		}

	      /* Must have found at least one sig. */
	      if (!rrsig_labels[nsecs_found])
		return 0;
	    }

	  nsecset[nsecs_found++] = pstart;   
	}
      
      if (!ADD_RDLEN(header, p, plen, rdlen))
	return 0;
    }
  
  if (type_found == T_NSEC)
    return prove_non_existence_nsec(header, plen, nsecset, rrsig_labels, nsecs_found, daemon->workspacename, keyname, name, qtype, nons);
  else if (type_found == T_NSEC3)
    return prove_non_existence_nsec3(header, plen, nsecset, nsecs_found, daemon->workspacename, keyname, name, qtype, wildname, nons);
  else
    return 0;
}

/* Check signing status of name.
   returns:
   STAT_SECURE   zone is signed.
   STAT_INSECURE zone proved unsigned.
   STAT_NEED_DS  require DS record of name returned in keyname.
   STAT_NEED_KEY require DNSKEY record of name returned in keyname.
   name returned unaltered.
*/
/**
 * @brief Determine DNSSEC validation state and next required DS record for zone chain
 *
 * @detailed
 * Determines validation state for zone by walking delegation chain from query name toward root,
 * looking for trust anchor (configured or cached DS record), then walking back from trust anchor
 * toward query name, checking DS record cache entries for each delegation point. Returns validation
 * state indicating if zone is secure (all DS records validated), insecure (break in chain of trust),
 * or needs additional DS record (STAT_NEED_DS with keyname set to required zone). Used by
 * dnssec_validate_reply() to determine which DS records must be fetched and validated before
 * answer can be validated. Handles empty non-terminals and insecure delegations. Computes next
 * keyname parameter for subsequent DS query or DNSKEY validation.
 *
 * @param name Query domain name to determine zone status, presentation format (e.g., "www.example.com")
 * @param class DNS class (typically C_IN=1 for Internet class)
 * @param keyname Output buffer for next zone name needing DS record or DNSKEY validation. Set to
 *                zone name from trust anchor toward query name where DS record needed. Must be at
 *                least MAXDNAME bytes. Modified on STAT_NEED_DS or STAT_SECURE return.
 * @param now Current time for cache lookup freshness checks
 *
 * @return Validation state for zone
 * @retval STAT_SECURE Zone validation chain complete from trust anchor to name. All DS records cached
 *                     and validated. Ready to validate DNSKEY at keyname (set to name).
 * @retval STAT_INSECURE Insecure delegation found in chain. Break in chain of trust, typically unsigned
 *                       zone (no DS record at delegation point, but proved via NSEC/NSEC3). Answer
 *                       treated as insecure (not validated).
 * @retval STAT_NEED_DS DS record needed for delegation point. keyname set to zone needing DS record.
 *                      Caller should query for DS keyname and validate via dnssec_validate_ds().
 * @retval STAT_NEED_KEY Similar to STAT_NEED_DS but explicitly requesting DNSKEY validation after DS
 *                       records obtained (implementation may use STAT_NEED_DS for same purpose).
 *
 * @note Trust anchor discovery: Walks from query name toward root looking for cached DS record with
 *       F_DS flag. If found, that's trust anchor. If not found, assumes root trust anchor (configured
 *       or built-in).
 * @note Delegation walk: After finding trust anchor, walks from trust anchor toward query name,
 *       checking cache for DS record at each delegation point. If DS missing, returns STAT_NEED_DS
 *       with keyname set to that zone.
 * @note DS cache entries: DS records cached with F_DS flag. F_NEG indicates proved non-existence of
 *       DS (insecure delegation). F_DNSSECOK misused to indicate non-existence of NS record (not
 *       delegation point, empty non-terminal).
 * @note Insecure delegation: If F_NEG DS record found without F_DNSSECOK, means no DS at delegation
 *       point (unsigned zone). Returns STAT_INSECURE.
 * @note Empty non-terminal: If F_NEG DS record found with F_DNSSECOK, means no NS record at name
 *       (empty non-terminal, not delegation). Continue walking toward query name.
 * @note Root trust anchor: If no cached DS found walking to root, assumes root trust anchor exists
 *       (from trust-anchors.conf or compiled-in).
 * @note Cache freshness: Uses now parameter to skip expired cache entries via cache_find_by_name().
 *
 * @warning Returns STAT_NEED_DS with keyname set if DS cache entry missing. Caller must fetch DS
 *          record via query.
 * @warning Modifies keyname on return (except STAT_INSECURE). Caller must check return value before
 *          using keyname.
 * @warning Assumes name is well-formed domain name (null-terminated, valid labels). No validation.
 * @warning Not thread-safe: modifies keyname buffer. Can be called concurrently with different keyname
 *          buffers.
 * @warning Cache lookups via cache_find_by_name() may return stale entries if cache not pruned
 *          (relies on now parameter).
 *
 * @see dnssec_validate_reply() which calls zone_status() to determine validation strategy
 * @see cache_find_by_name() used for DS record cache lookups
 * @see dnssec_validate_ds() called to validate fetched DS records
 * @see dnssec_validate_by_ds() called after zone chain established to validate answer DNSKEYs
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME] = "www.example.com";
 * char keyname[MAXDNAME];
 * int status = zone_status(name, C_IN, keyname, time(NULL));
 * if (status == STAT_NEED_DS) {
 *     // Need to query for DS keyname
 *     query_ds_record(keyname);
 * } else if (status == STAT_SECURE) {
 *     // Chain complete, validate DNSKEY at keyname
 *     validate_dnskey(keyname);
 * } else if (status == STAT_INSECURE) {
 *     // Insecure delegation, treat answer as insecure
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements chain of trust validation per RFC 4035 Section 5. DS record semantics
 * per RFC 4034 Section 5. Insecure delegation handling per RFC 4035 Section 5.2.
 *
 * SIDE EFFECTS:
 * - Searches cache via cache_find_by_name() for F_DS entries (may update cache LRU)
 * - Writes zone name to keyname buffer on STAT_NEED_DS or STAT_SECURE return
 * - Uses strcpy() and strchr() on name and keyname
 * - No memory allocation
 *
 * THREAD SAFETY: Thread-safe for cache lookups (cache has internal locking). Modifies keyname buffer
 * (caller must use separate buffers for concurrent calls).
 */
static int zone_status(char *name, int class, char *keyname, time_t now)
{
  int name_start = strlen(name); /* for when TA is root */
  struct crec *crecp;
  char *p;

  /* First, work towards the root, looking for a trust anchor.
     This can either be one configured, or one previously cached.
     We can assume, if we don't find one first, that there is
     a trust anchor at the root. */
  for (p = name; p; p = strchr(p, '.'))
    {
      if (*p == '.')
	p++;

      if (cache_find_by_name(NULL, p, now, F_DS))
	{
	  name_start = p - name;
	  break;
	}
    }

  /* Now work away from the trust anchor */
  while (1)
    {
      strcpy(keyname, &name[name_start]);
      
      if (!(crecp = cache_find_by_name(NULL, keyname, now, F_DS)))
	return STAT_NEED_DS;
      
       /* F_DNSSECOK misused in DS cache records to non-existence of NS record.
	  F_NEG && !F_DNSSECOK implies that we've proved there's no DS record here,
	  but that's because there's no NS record either, ie this isn't the start
	  of a zone. We only prove that the DNS tree below a node is unsigned when
	  we prove that we're at a zone cut AND there's no DS record. */
      if (crecp->flags & F_NEG)
	{
	  if (crecp->flags & F_DNSSECOK)
	    return STAT_INSECURE; /* proved no DS here */
	}
      else
	{
	  /* If all the DS records have digest and/or sig algos we don't support,
	     then the zone is insecure. Note that if an algo
	     appears in the DS, then RRSIGs for that algo MUST
	     exist for each RRset: 4035 para 2.2  So if we find
	     a DS here with digest and sig we can do, we're entitled
	     to assume we can validate the zone and if we can't later,
	     because an RRSIG is missing we return BOGUS.
	  */
	  do 
	    {
	      if (crecp->uid == (unsigned int)class &&
		  ds_digest_name(crecp->addr.ds.digest) &&
		  algo_digest_name(crecp->addr.ds.algo))
		break;
	    }
	  while ((crecp = cache_find_by_name(crecp, keyname, now, F_DS)));

	  if (!crecp)
	    return STAT_INSECURE;
	}

      if (name_start == 0)
	break;

      for (p = &name[name_start-2]; (*p != '.') && (p != name); p--);
      
      if (p != name)
        p++;
      
      name_start = p - name;
    } 

  return STAT_SECURE;
}
       
/* Validate all the RRsets in the answer and authority sections of the reply (4035:3.2.3) 
   Return code:
   STAT_SECURE   if it validates.
   STAT_INSECURE at least one RRset not validated, because in unsigned zone.
   STAT_BOGUS    signature is wrong, bad packet, no validation where there should be.
   STAT_NEED_KEY need DNSKEY to complete validation (name is returned in keyname, class in *class)
   STAT_NEED_DS  need DS to complete validation (name is returned in keyname)

   daemon->rr_status points to a char array which corressponds to the RRs in the 
   answer and auth sections. This is set to >1 for each RR which is validated, and 0 for any which aren't.

   When validating replies to DS records, we're only interested in the NSEC{3} RRs in the auth section.
   Other RRs in that section missing sigs will not cause am INSECURE reply. We determine this mode
   is the nons argument is non-NULL.
*/

/**
 * @brief Main DNSSEC validation entry point for complete DNS response validation
 *
 * @detailed
 * Comprehensive DNSSEC validation of entire DNS response including answer, authority, and additional
 * sections. Validates all RRsets against their RRSIG signatures per RFC 4035 Section 5.3. Handles
 * CNAME chains by following CNAMEs and validating each link. Processes negative answers (NXDOMAIN,
 * NODATA) by validating NSEC/NSEC3 denial-of-existence proofs per RFC 4035 Section 5.4 and RFC 5155.
 * Detects wildcard expansion and validates wildcard proofs. Distinguishes secure (valid signatures),
 * insecure (unsigned zones), and bogus (invalid signatures) states. Caches validation results with
 * RRsets. This is the primary validation function called by forward.c for all DNSSEC-enabled queries.
 *
 * Special DS validation mode: When validating DS responses (nons != NULL), only validates NSEC/NSEC3
 * in authority section, allowing other authority records to be unsigned without triggering INSECURE.
 * This accommodates parent zones that may have mixed signed/unsigned authority sections.
 *
 * @param now Current time for cache lookups and timestamp validation
 * @param header DNS packet header containing complete response with answer/authority/additional
 *               sections. MUST have exactly one question (qdcount == 1). RCODE must be NOERROR,
 *               NXDOMAIN, or other (SERVFAIL/REFUSED return STAT_BOGUS/STAT_INSECURE).
 * @param plen Packet length in bytes for bounds checking
 * @param name Query name in presentation format. Modified during CNAME following. Must be at least
 *             MAXDNAME bytes.
 * @param keyname Workspace buffer for DNSKEY signer names during validation. Output buffer for
 *                STAT_NEED_KEY/STAT_NEED_DS cases. Must be at least MAXDNAME bytes.
 * @param class Optional input/output DNS class pointer. If non-NULL, provides class filter and
 *              receives validated class on success. If NULL, class extracted from question.
 * @param check_unsigned If true, unsigned RRsets in signed zone cause STAT_BOGUS return (strict mode).
 *                       If false, unsigned RRsets allowed (permissive mode for DS validation).
 * @param neganswer Output flag: set to 1 if negative answer (NXDOMAIN/NODATA) with valid NSEC/NSEC3
 *                  proof, else 0. May be NULL if caller doesn't need negative answer detection.
 * @param nons Optional output for DS validation mode. If non-NULL, enables DS-specific validation:
 *             only NSEC/NSEC3 in authority section validated, other unsigned authority records ignored.
 *             Set to 1 if NSEC/NSEC3 found in authority section.
 * @param nsec_ttl Output TTL from validated NSEC/NSEC3 records for negative answer caching.
 *                 Relevant only when neganswer == 1. May be NULL if caller doesn't need TTL.
 *
 * @return Validation status with optional flags
 * @retval STAT_SECURE All RRsets validate successfully, complete chain of trust verified
 * @retval STAT_SECURE_WILDCARD Validates with wildcard expansion detected
 * @retval STAT_INSECURE Unsigned zone (no DS at delegation) or unsigned data in unsigned zone,
 *         not necessarily an error but no cryptographic security
 * @retval STAT_BOGUS Invalid signatures, bad packet format, unsigned data in signed zone,
 *         or validation failure
 * @retval STAT_NEED_KEY DNSKEY required for validation not in cache. keyname contains signer name.
 * @retval STAT_NEED_DS DS record required for validation not in cache. keyname contains zone name.
 *
 * @note Query type T_RRSIG returns STAT_INSECURE immediately (cannot validate RRSIG queries).
 * @note RCODE SERVFAIL or qdcount != 1 returns STAT_BOGUS (invalid packet).
 * @note RCODE other than NOERROR/NXDOMAIN returns STAT_INSECURE (cannot validate unusual responses).
 * @note Follows CNAME chains, validating each CNAME link before following target.
 * @note Validates answer, authority, and additional sections unless DS mode (nons != NULL).
 * @note Extends daemon->rr_status array if needed to track per-RR validation status.
 * @note Wildcard expansion detected via RRSIG labels field per RFC 4035 Section 5.3.2.
 * @note Negative answers require valid NSEC or NSEC3 proofs per RFC 4035 Section 5.4.
 *
 * @warning Extensive validation is CPU-intensive (multiple RSA/ECDSA signature verifications).
 * @warning Uses static targets array for CNAME chain tracking. Not thread-safe.
 * @warning Memory allocation failure (rr_status, targets) returns STAT_BOGUS.
 * @warning Calls validate_rrset() which uses static rrset/sigs arrays. Not reentrant.
 *
 * @see dnssec_validate_by_ds() for DNSKEY validation against parent DS
 * @see dnssec_validate_ds() for DS record validation
 * @see validate_rrset() for individual RRset signature verification
 * @see prove_non_existence() for NSEC/NSEC3 denial-of-existence validation
 * @see RFC 4035 Section 5.3 for DNSSEC validation algorithm
 * @see RFC 4035 Section 5.4 for authenticated denial of existence
 * @see RFC 5155 for NSEC3 validation
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME], keyname[MAXDNAME];
 * int class_in = C_IN, neganswer, nons, nsec_ttl;
 * int result = dnssec_validate_reply(now, header, plen, name, keyname,
 *                                     &class_in, 1, &neganswer, NULL, &nsec_ttl);
 * if (result == STAT_SECURE) {
 *     // All RRsets validate, cache answer as secure
 * } else if (result == STAT_NEED_KEY) {
 *     // Fetch DNSKEY for keyname
 * } else if (result == STAT_BOGUS) {
 *     // Invalid signatures, return SERVFAIL to client
 * } else if (result == STAT_INSECURE && neganswer) {
 *     // Negative answer validated, cache with nsec_ttl
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4035 Section 5 DNSSEC validation protocol, RFC 4035 Section 5.3
 * RRset validation, RFC 4035 Section 5.4 authenticated denial of existence, RFC 5155 NSEC3 validation,
 * RFC 4035 Section 5.3.2 wildcard expansion validation, RFC 4035 Section 2.2 CNAME chain validation.
 *
 * SIDE EFFECTS:
 * - Modifies name buffer during CNAME following and name extraction
 * - Modifies keyname buffer during validation
 * - Extends daemon->rr_status array if needed (may allocate/free via whine_malloc)
 * - Zeros daemon->rr_status array at start
 * - Extends static targets array for CNAME chain tracking
 * - Calls validate_rrset() which uses static rrset/sigs arrays and has extensive side effects
 * - Calls prove_non_existence() for negative answer validation
 * - Sets *neganswer, *nons, *nsec_ttl, *class output parameters if non-NULL
 *
 * THREAD SAFETY: NOT thread-safe. Uses static targets array and calls validate_rrset() which uses
 * static arrays. Uses daemon->rr_status global. Not reentrant.
 */
int dnssec_validate_reply(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, 
			  int *class, int check_unsigned, int *neganswer, int *nons, int *nsec_ttl)
{
  static unsigned char **targets = NULL;
  static int target_sz = 0;

  unsigned char *ans_start, *p1, *p2;
  int type1, class1, rdlen1 = 0, type2, class2, rdlen2, qclass, qtype, targetidx;
  int i, j, rc = STAT_INSECURE;
  int secure = STAT_SECURE;
   
  /* extend rr_status if necessary */
  if (daemon->rr_status_sz < ntohs(header->ancount) + ntohs(header->nscount))
    {
      unsigned long *new = whine_malloc(sizeof(*daemon->rr_status) * (ntohs(header->ancount) + ntohs(header->nscount) + 64));

      if (!new)
	return STAT_BOGUS;

      free(daemon->rr_status);
      daemon->rr_status = new;
      daemon->rr_status_sz = ntohs(header->ancount) + ntohs(header->nscount) + 64;
    }
  
  memset(daemon->rr_status, 0, sizeof(*daemon->rr_status) * daemon->rr_status_sz);
  
  if (neganswer)
    *neganswer = 0;
  
  if (RCODE(header) == SERVFAIL || ntohs(header->qdcount) != 1)
    return STAT_BOGUS;
  
  if (RCODE(header) != NXDOMAIN && RCODE(header) != NOERROR)
    return STAT_INSECURE;

  p1 = (unsigned char *)(header+1);
  
   /* Find all the targets we're looking for answers to.
     The zeroth array element is for the query, subsequent ones
     for CNAME targets, unless the query is for a CNAME or ANY. */

  if (!expand_workspace(&targets, &target_sz, 0))
    return STAT_BOGUS;
  
  targets[0] = p1;
  targetidx = 1;
   
  if (!extract_name(header, plen, &p1, name, 1, 4))
    return STAT_BOGUS;
  
  GETSHORT(qtype, p1);
  GETSHORT(qclass, p1);
  ans_start = p1;
 
  /* Can't validate an RRSIG query */
  if (qtype == T_RRSIG)
    return STAT_INSECURE;
  
  if (qtype != T_CNAME && qtype != T_ANY)
    for (j = ntohs(header->ancount); j != 0; j--) 
      {
	if (!(p1 = skip_name(p1, header, plen, 10)))
	  return STAT_BOGUS; /* bad packet */
	
	GETSHORT(type2, p1); 
	p1 += 6; /* class, TTL */
	GETSHORT(rdlen2, p1);  
	
	if (type2 == T_CNAME)
	  {
	    if (!expand_workspace(&targets, &target_sz, targetidx))
	      return STAT_BOGUS;
	    
	    targets[targetidx++] = p1; /* pointer to target name */
	  }
	
	if (!ADD_RDLEN(header, p1, plen, rdlen2))
	  return STAT_BOGUS;
      }
  
  for (p1 = ans_start, i = 0; i < ntohs(header->ancount) + ntohs(header->nscount); i++)
    {
      if (i != 0 && !ADD_RDLEN(header, p1, plen, rdlen1))
	return STAT_BOGUS;
      
      if (!extract_name(header, plen, &p1, name, 1, 10))
	return STAT_BOGUS; /* bad packet */
      
      GETSHORT(type1, p1);
      GETSHORT(class1, p1);
      p1 += 4; /* TTL */
      GETSHORT(rdlen1, p1);
      
      /* Don't try and validate RRSIGs! */
      if (type1 == T_RRSIG)
	continue;
      
      /* Check if we've done this RRset already */
      for (p2 = ans_start, j = 0; j < i; j++)
	{
	  if (!(rc = extract_name(header, plen, &p2, name, 0, 10)))
	    return STAT_BOGUS; /* bad packet */
	  
	  GETSHORT(type2, p2);
	  GETSHORT(class2, p2);
	  p2 += 4; /* TTL */
	  GETSHORT(rdlen2, p2);
	  
	  if (type2 == type1 && class2 == class1 && rc == 1)
	    break; /* Done it before: name, type, class all match. */
	  
	  if (!ADD_RDLEN(header, p2, plen, rdlen2))
	    return STAT_BOGUS;
	}
      
      /* Done already: copy the validation status */
      if (j != i)
	daemon->rr_status[i] = daemon->rr_status[j];
      else
	{
	  /* Not done, validate now */
	  int sigcnt, rrcnt;
	  char *wildname;
	  
	  if (!explore_rrset(header, plen, class1, type1, name, keyname, &sigcnt, &rrcnt))
	    return STAT_BOGUS;
	  
	  /* No signatures for RRset. We can be configured to assume this is OK and return an INSECURE result. */
	  if (sigcnt == 0)
	    {
	      /* NSEC and NSEC3 records must be signed. We make this assumption elsewhere. */
	      if (type1 == T_NSEC || type1 == T_NSEC3)
		return STAT_BOGUS | DNSSEC_FAIL_NOSIG;
	      else if (nons && i >= ntohs(header->ancount))
		/* If we're validating a DS reply, rather than looking for the value of AD bit,
		   we only care that NSEC and NSEC3 RRs in the auth section are signed. 
		   Return SECURE even if others (SOA....) are not. */
		rc = STAT_SECURE;
	      else
		{
		  /* unsigned RRsets in auth section are not BOGUS, but do make reply insecure. */
		  if (check_unsigned && i < ntohs(header->ancount))
		    {
		      rc = zone_status(name, class1, keyname, now);
		      if (STAT_ISEQUAL(rc, STAT_SECURE))
			rc = STAT_BOGUS | DNSSEC_FAIL_NOSIG;
		      
		      if (class)
			*class = class1; /* Class for NEED_DS or NEED_KEY */
		    }
		  else 
		    rc = STAT_INSECURE; 
		  
		  if (!STAT_ISEQUAL(rc, STAT_INSECURE))
		    return rc;
		}
	    }
	  else
	    {
	      /* explore_rrset() gives us key name from sigs in keyname.
		 Can't overwrite name here. */
	      strcpy(daemon->workspacename, keyname);
	      rc = zone_status(daemon->workspacename, class1, keyname, now);
	      
	      if (STAT_ISEQUAL(rc, STAT_BOGUS) || STAT_ISEQUAL(rc, STAT_NEED_KEY) || STAT_ISEQUAL(rc, STAT_NEED_DS))
		{
		  if (class)
		    *class = class1; /* Class for NEED_DS or NEED_KEY */
		  return rc;
		}
	      
	      /* Zone is insecure, don't need to validate RRset */
	      if (STAT_ISEQUAL(rc, STAT_SECURE))
		{
		  unsigned long sig_ttl;
		  rc = validate_rrset(now, header, plen, class1, type1, sigcnt,
				      rrcnt, name, keyname, &wildname, NULL, 0, 0, 0, &sig_ttl);
		  
		  if (STAT_ISEQUAL(rc, STAT_BOGUS) || STAT_ISEQUAL(rc, STAT_NEED_KEY) || STAT_ISEQUAL(rc, STAT_NEED_DS))
		    {
		      if (class)
			*class = class1; /* Class for DS or DNSKEY */
		      return rc;
		    } 
		  
		  /* rc is now STAT_SECURE or STAT_SECURE_WILDCARD */
		  
		  /* Note that RR is validated */
		  daemon->rr_status[i] = sig_ttl;
		   
		  /* Note if we've validated either the answer to the question
		     or the target of a CNAME. Any not noted will need NSEC or
		     to be in unsigned space. */
		  for (j = 0; j <targetidx; j++)
		    if ((p2 = targets[j]))
		      {
			int rc1;
			if (!(rc1 = extract_name(header, plen, &p2, name, 0, 10)))
			  return STAT_BOGUS; /* bad packet */
			
			if (class1 == qclass && rc1 == 1 && (type1 == T_CNAME || type1 == qtype || qtype == T_ANY ))
			  targets[j] = NULL;
		      }
		  
		  /* An attacker replay a wildcard answer with a different
		     answer and overlay a genuine RR. To prove this
		     hasn't happened, the answer must prove that
		     the genuine record doesn't exist. Check that here. 
		     Note that we may not yet have validated the NSEC/NSEC3 RRsets. 
		     That's not a problem since if the RRsets later fail
		     we'll return BOGUS then. */
		  if (STAT_ISEQUAL(rc, STAT_SECURE_WILDCARD) &&
		      !prove_non_existence(header, plen, keyname, name, type1, class1, wildname, NULL, NULL))
		    return STAT_BOGUS | DNSSEC_FAIL_NONSEC;

		  rc = STAT_SECURE;
		}
	    }
	}

      if (STAT_ISEQUAL(rc, STAT_INSECURE))
	secure = STAT_INSECURE;
    }

  /* OK, all the RRsets validate, now see if we have a missing answer or CNAME target. */
  for (j = 0; j <targetidx; j++)
    if ((p2 = targets[j]))
      {
	if (neganswer)
	  *neganswer = 1;
	
	if (!extract_name(header, plen, &p2, name, 1, 10))
	  return STAT_BOGUS; /* bad packet */
	
	/* NXDOMAIN or NODATA reply, unanswered question is (name, qclass, qtype) */
	
	/* For anything other than a DS record, this situation is OK if either
	   the answer is in an unsigned zone, or there's a NSEC records. */
	if (!prove_non_existence(header, plen, keyname, name, qtype, qclass, NULL, nons, nsec_ttl))
	  {
	    /* Empty DS without NSECS */
	    if (qtype == T_DS)
	      return STAT_BOGUS | DNSSEC_FAIL_NONSEC;
	    
	    if (!STAT_ISEQUAL((rc = zone_status(name, qclass, keyname, now)), STAT_SECURE))
	      {
		if (class)
		  *class = qclass; /* Class for NEED_DS or NEED_KEY */
		return rc;
	      } 
	    
	    return STAT_BOGUS | DNSSEC_FAIL_NONSEC; /* signed zone, no NSECs */
	  }
      }
  
  return secure;
}


/* Compute keytag (checksum to quickly index a key). See RFC4034 */
/**
 * @brief Compute DNSKEY key tag identifier per RFC 4034 Appendix B
 *
 * @detailed
 * Computes DNSKEY key tag (16-bit identifier) used to match DNSKEY records with RRSIG and DS records
 * per RFC 4034 Appendix B. Key tag is not unique but acts as quick filter to avoid trying all DNSKEYs
 * when verifying RRSIG. Algorithm depends on DNSKEY algorithm: legacy RSAMD5 (algorithm 1) uses simple
 * last 2 bytes of key, all other algorithms use RFC 4034 Appendix B.1 checksum over flags, protocol,
 * algorithm, and public key bytes. Result is 16-bit unsigned integer. Used to match RRSIG key tag field
 * to DNSKEY, and DS key tag field to DNSKEY. Collisions possible (multiple keys with same tag), so
 * cryptographic verification still required after tag match.
 *
 * @param alg DNSKEY algorithm number (e.g., 1=RSAMD5, 5=RSASHA1, 8=RSASHA256, 13=ECDSAP256SHA256,
 *            15=ED25519). Algorithm 1 uses different keytag calculation per RFC 4034 Appendix B.1.
 * @param flags DNSKEY flags field (16-bit). Bit 7 (0x0100) = Zone Key flag, bit 15 (0x8000) = Secure
 *              Entry Point (SEP) flag for KSK. Used in keytag checksum.
 * @param key DNSKEY public key bytes (wire format, algorithm-specific encoding). For RSA, includes
 *            exponent length, exponent, modulus per RFC 3110. For ECDSA/EdDSA, algorithm-specific
 *            point encoding.
 * @param keylen Length of key buffer in bytes. Typically 32-512 bytes depending on algorithm and
 *               key size.
 *
 * @return 16-bit DNSKEY key tag
 * @retval 0-65535 Computed key tag value used for matching RRSIG and DS records
 *
 * @note Key tag purpose: Quick filter to identify candidate DNSKEY for RRSIG verification or DS
 *       matching. Not cryptographically secure identifier (collisions possible).
 * @note Algorithm 1 (RSAMD5): Uses last 2 bytes of key as key tag per RFC 4034 Appendix B.1. Deprecated
 *       algorithm (RSAMD5 considered insecure), rarely used.
 * @note Other algorithms: Uses RFC 4034 Appendix B.1 checksum: sum of flags, protocol (0x0300), algorithm,
 *       and key bytes (alternating 8-bit left shifts), then fold upper 16 bits into lower 16 bits.
 * @note Protocol field: Always 3 (DNSSEC) per RFC 4034. Hardcoded as 0x0300 in checksum computation.
 * @note RRSIG matching: RRSIG key tag field compared to DNSKEY key tag. If match, try cryptographic
 *       verification. If no match, skip DNSKEY (optimization).
 * @note DS matching: DS key tag field must match DNSKEY key tag for DS to refer to that DNSKEY. Multiple
 *       DS records can exist with same key tag (different digest algorithms).
 * @note Collision handling: If multiple DNSKEYs have same key tag, validator must try all matching keys
 *       until cryptographic verification succeeds.
 *
 * @warning Algorithm 1 computation assumes keylen >= 4 (needs last 4 bytes, uses last 2 for tag). If
 *          keylen < 4, buffer underflow. Caller must validate keylen.
 * @warning Key buffer must be valid for keylen bytes. No bounds checking.
 * @warning Key tag is NOT unique. Collisions possible. Cannot rely on key tag alone for security.
 * @warning Does not validate algorithm number. Invalid algorithm uses RFC 4034 checksum (not algorithm 1
 *          path).
 *
 * @see validate_rrset() which calls dnskey_keytag() to match RRSIG to DNSKEY
 * @see dnssec_validate_ds() which calls dnskey_keytag() to match DS to DNSKEY
 * @see RFC 4034 Appendix B for key tag calculation algorithm
 * @see RFC 4034 Section 2 for DNSKEY RDATA format
 * @see RFC 4034 Section 5 for DS RDATA format (includes key tag field)
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char key[256] = { // DNSKEY public key bytes };
 * int keylen = 256;
 * int flags = 0x0101; // Zone Key flag
 * int alg = 8; // RSASHA256
 * int tag = dnskey_keytag(alg, flags, key, keylen);
 * // Compare tag with RRSIG key tag field
 * if (tag == rrsig_key_tag) {
 *     // Try cryptographic verification with this DNSKEY
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 4034 Appendix B key tag calculation. RFC 4034 Appendix B.1 algorithm 1
 * special case.
 *
 * SIDE EFFECTS:
 * - Reads flags, alg, key, keylen parameters
 * - Computes checksum via loop over key bytes
 * - No memory allocation, no external state modification
 *
 * THREAD SAFETY: Thread-safe. Pure function, no shared state.
 */
int dnskey_keytag(int alg, int flags, unsigned char *key, int keylen)
{
  if (alg == 1)
    {
      /* Algorithm 1 (RSAMD5) has a different (older) keytag calculation algorithm.
         See RFC4034, Appendix B.1 */
      return key[keylen-4] * 256 + key[keylen-3];
    }
  else
    {
      unsigned long ac = flags + 0x300 + alg;
      int i;

      for (i = 0; i < keylen; ++i)
        ac += (i & 1) ? key[i] : key[i] << 8;

      ac += (ac >> 16) & 0xffff;
      return ac & 0xffff;
    }
}

/**
 * @brief Generate DNSSEC query packet for DS, DNSKEY, or other DNSSEC record types
 *
 * @detailed
 * Constructs DNS query packet for DNSSEC record types (DS, DNSKEY, RRSIG, etc.) with DNSSEC extensions
 * enabled (DO bit set in EDNS0 OPT record). Uses existing DNS packet building infrastructure from
 * rfc1035.c. Sets query ID (from daemon->log_id), recursion desired (RD) flag, and adds EDNS0 OPT
 * record with DNSSEC OK (DO) flag set per RFC 4035 Section 3.2.1. Returns constructed packet size.
 * Used by dnssec_validate_reply() and validation infrastructure to fetch missing DS or DNSKEY records
 * needed for validation chain. Packet ready for transmission to upstream DNS server.
 *
 * @param header DNS packet header buffer to fill. Must be zeroed or initialized before call. Query ID,
 *               flags (RD=1), qdcount, ancount, nscount, arcount fields set by this function. Must have
 *               space for question section and EDNS0 OPT record.
 * @param end Pointer to end of header buffer (one past last valid byte). Used for bounds checking to
 *            prevent buffer overflow during packet construction.
 * @param name Query domain name, presentation format (e.g., "example.com" for DS, "www.example.com"
 *             for DNSKEY). Converted to wire format (length-prefixed labels) in packet.
 * @param class DNS class (typically C_IN=1 for Internet class)
 * @param type DNS query type (e.g., T_DS=43 for DS records, T_DNSKEY=48 for DNSKEY records, T_RRSIG=46
 *             for RRSIGs). Any valid DNS type supported.
 * @param edns_pktsz EDNS0 UDP payload size for OPT record (e.g., 4096 for EDNS_PKTSZ). Indicates maximum
 *                   UDP response size validator can receive. Per RFC 6891 Section 6.2.3.
 *
 * @return Size of constructed query packet in bytes
 * @retval >0 Success, packet size from start of header to end of EDNS0 OPT record. Packet ready for
 *            transmission.
 * @retval 0 Failure: buffer too small (end - header insufficient), add_resource_record() failed, or
 *           packet construction error
 *
 * @note Query ID: Set from daemon->log_id (global query counter for logging). Incremented for each query.
 * @note Query flags: Sets RD (Recursion Desired) flag. Does not set other flags (AA, TC, RA, AD, CD all
 *       clear).
 * @note EDNS0 OPT: Adds OPT pseudo-RR in additional section per RFC 6891. DO (DNSSEC OK) flag set in
 *       extended flags field per RFC 4035 Section 3.2.1.
 * @note DO flag: Indicates validator can handle DNSSEC records (RRSIG, DNSKEY, DS, NSEC, NSEC3) in
 *       response. Server should include DNSSEC RRs if DO=1.
 * @note UDP payload size: edns_pktsz typically 4096 (EDNS_PKTSZ). Larger values (up to 65535) possible
 *       but may cause fragmentation. Per RFC 6891.
 * @note Packet format: Standard DNS query packet with question section (name, type, class) plus EDNS0
 *       OPT record in additional section.
 * @note Buffer size: Caller must ensure header buffer large enough for query (typically 512+ bytes for
 *       EDNS0 query).
 *
 * @warning Returns 0 if buffer too small. Caller must check return value before using packet.
 * @warning Assumes header buffer zeroed or initialized. Old data in header may corrupt packet.
 * @warning Assumes name is well-formed domain name (null-terminated, valid labels). No validation.
 * @warning Modifies header buffer contents. Not idempotent (calling twice on same buffer corrupts
 *          packet).
 * @warning Uses daemon->log_id global for query ID. Not thread-safe if daemon->log_id modified
 *          concurrently.
 *
 * @see dnssec_validate_reply() which calls dnssec_generate_query() to construct DS/DNSKEY queries
 * @see add_resource_record() in rfc1035.c used to add EDNS0 OPT record
 * @see RFC 4035 Section 3.2.1 for DNSSEC OK (DO) bit in EDNS0
 * @see RFC 6891 for EDNS0 OPT record format and UDP payload size
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header header_buf;
 * unsigned char *end = ((unsigned char *)&header_buf) + sizeof(header_buf);
 * char name[MAXDNAME] = "example.com";
 * size_t pkt_size = dnssec_generate_query(&header_buf, end, name, C_IN, T_DS, 4096);
 * if (pkt_size > 0) {
 *     // Send packet to upstream server
 *     send_dns_query(&header_buf, pkt_size);
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Generates RFC 1035 DNS query packet with RFC 4035 Section 3.2.1 DNSSEC extensions
 * (DO bit). RFC 6891 EDNS0 OPT record format.
 *
 * SIDE EFFECTS:
 * - Writes to header buffer (query ID, flags, counts, question section, EDNS0 OPT)
 * - Reads daemon->log_id global (incremented externally, not by this function)
 * - Calls add_resource_record() to append EDNS0 OPT (may have side effects in rfc1035.c)
 * - No memory allocation
 *
 * THREAD SAFETY: NOT fully thread-safe. Reads daemon->log_id global. header buffer must be thread-local.
 * Can be called concurrently if header buffers separate and daemon->log_id access synchronized.
 */
size_t dnssec_generate_query(struct dns_header *header, unsigned char *end, char *name, int class, 
			     int type, int edns_pktsz)
{
  unsigned char *p;
  size_t ret;

  header->qdcount = htons(1);
  header->ancount = htons(0);
  header->nscount = htons(0);
  header->arcount = htons(0);

  header->hb3 = HB3_RD; 
  SET_OPCODE(header, QUERY);
  /* For debugging, set Checking Disabled, otherwise, have the upstream check too,
     this allows it to select auth servers when one is returning bad data. */
  header->hb4 = option_bool(OPT_DNSSEC_DEBUG) ? HB4_CD : 0;

  /* ID filled in later */

  p = (unsigned char *)(header+1);
	
  p = do_rfc1035_name(p, name, NULL);
  *p++ = 0;
  PUTSHORT(type, p);
  PUTSHORT(class, p);

  ret = add_do_bit(header, p - (unsigned char *)header, end);

  if (find_pseudoheader(header, ret, NULL, &p, NULL, NULL))
    PUTSHORT(edns_pktsz, p);

  return ret;
}

/**
 * @brief Convert DNSSEC validation error flags to Extended DNS Error (EDE) code
 *
 * @detailed
 * Converts internal DNSSEC validation failure flags to standardized Extended DNS Error (EDE) codes
 * per RFC 8914 for communication in DNS responses. DNSSEC validation can fail with multiple error
 * flags set (e.g., no RRSIG and expired signature), so this function prioritizes errors and returns
 * single most critical EDE code. Priority order: signature not yet valid (NYV), signature expired,
 * unsupported DNSKEY algorithm, no zone key, no DNSKEY, unsupported DS algorithm, no NSEC, indeterminate,
 * no RRSIG. EDE codes included in EDNS0 OPT record extended errors option in SERVFAIL responses to
 * provide clients detailed validation failure reasons. Improves DNSSEC debugging and error reporting.
 *
 * @param status DNSSEC validation failure flags (bitmask of DNSSEC_FAIL_* constants from dnsmasq.h).
 *               Multiple flags can be set. Examples: DNSSEC_FAIL_NOSIG (no RRSIG), DNSSEC_FAIL_EXP
 *               (expired signature), DNSSEC_FAIL_NOKEY (no matching DNSKEY), DNSSEC_FAIL_NYV (signature
 *               not yet valid), DNSSEC_FAIL_INDET (indeterminate validation), DNSSEC_FAIL_NOZONE (no
 *               zone key/DS), DNSSEC_FAIL_NONSEC (no NSEC/NSEC3 proof), DNSSEC_FAIL_NOKEYSUP (unsupported
 *               DNSKEY algorithm), DNSSEC_FAIL_NODSSUP (unsupported DS algorithm).
 *
 * @return Extended DNS Error code per RFC 8914
 * @retval EDE_SIG_NYV (8) Signature not yet valid (inception time in future, clock skew or wrong time)
 * @retval EDE_SIG_EXP (7) Signature expired (expiration time in past, needs re-signing or clock skew)
 * @retval EDE_USUPDNSKEY (10) Unsupported DNSKEY algorithm (validator doesn't support algorithm in DNSKEY)
 * @retval EDE_NO_ZONEKEY (11) No zone key bit set (DNSKEY missing zone key flag)
 * @retval EDE_NO_DNSKEY (9) No DNSKEY RR found (missing DNSKEY for RRSIG verification)
 * @retval EDE_USUPDS (6) Unsupported DS digest algorithm (validator doesn't support DS hash algorithm)
 * @retval EDE_NO_NSEC (12) NSEC/NSEC3 missing (denial-of-existence proof incomplete)
 * @retval EDE_DNSSEC_IND (13) DNSSEC indeterminate (unable to validate, missing data or network error)
 * @retval EDE_NO_RRSIG (14) No RRSIG found (missing signature for validation)
 * @retval EDE_UNSET (0) No error or unknown error (fallback if no flags match)
 *
 * @note Error priority: Designed to report most actionable error first. Time-based errors (NYV, EXP)
 *       prioritized highest (likely clock skew or zone needs re-signing). Algorithm errors next
 *       (upgrade validator or zone). Missing records last (configuration or network issues).
 * @note Multiple flags: Validation can set multiple failure flags (e.g., DNSSEC_FAIL_NOSIG |
 *       DNSSEC_FAIL_NOKEY). This function returns single EDE code representing primary failure cause.
 * @note EDE codes: Defined in RFC 8914 INFO codes (not error RCODEs). Included in EDNS0 OPT extended
 *       errors option in SERVFAIL responses.
 * @note Client usage: Clients receiving EDE codes can provide better error messages to users or
 *       automatically retry with adjusted parameters (e.g., clock synchronization for NYV/EXP).
 * @note Logging: EDE codes also used for detailed logging of validation failures in dnsmasq logs.
 * @note EDE constants: Defined in dnsmasq.h (EDE_SIG_NYV, EDE_SIG_EXP, etc.). Numeric values per
 *       RFC 8914 IANA registry.
 *
 * @warning Returns EDE_UNSET (0) if status is 0 or contains no recognized flags. Caller should handle
 *          EDE_UNSET appropriately (generic DNSSEC failure message).
 * @warning Priority logic means some errors masked if multiple set. E.g., if DNSSEC_FAIL_NYV and
 *          DNSSEC_FAIL_NOSIG both set, only EDE_SIG_NYV returned. Complete error details in logs, not
 *          in EDE.
 * @warning EDE codes intended for SERVFAIL responses. Should not be included in NOERROR or NXDOMAIN
 *          responses (not validation failures).
 * @warning Does not validate status value. Invalid status (no recognized flags) returns EDE_UNSET.
 *
 * @see dnssec_validate_reply() which sets DNSSEC_FAIL_* flags on validation failures
 * @see validate_rrset() which sets DNSSEC_FAIL_EXP, DNSSEC_FAIL_NYV on RRSIG time checks
 * @see RFC 8914 for Extended DNS Errors (EDE) specification and INFO code registry
 * @see dnsmasq.h for DNSSEC_FAIL_* flag definitions and EDE_* code definitions
 *
 * EXAMPLE USAGE:
 * @code
 * int status = DNSSEC_FAIL_EXP | DNSSEC_FAIL_NOSIG; // Multiple errors
 * int ede_code = errflags_to_ede(status);
 * // ede_code = EDE_SIG_EXP (7) because EXP prioritized over NOSIG
 * // Include ede_code in EDNS0 extended errors option in SERVFAIL response
 * add_ede_option(response, ede_code);
 * @endcode
 *
 * RFC COMPLIANCE: Implements RFC 8914 Extended DNS Errors mapping for DNSSEC validation failures.
 * Provides standardized error codes for DNSSEC debugging.
 *
 * SIDE EFFECTS:
 * - Reads status parameter
 * - No memory allocation, no state modification
 * - Pure function
 *
 * THREAD SAFETY: Thread-safe. Pure function, no shared state.
 */
int errflags_to_ede(int status)
{
  /* We can end up with more than one flag set for some errors,
     so this encodes a rough priority so the (eg) No sig is reported
     before no-unexpired-sig. */

  if (status & DNSSEC_FAIL_NYV)
    return EDE_SIG_NYV;
  else if (status & DNSSEC_FAIL_EXP)
    return EDE_SIG_EXP;
  else if (status & DNSSEC_FAIL_NOKEYSUP)
    return EDE_USUPDNSKEY;
  else if (status & DNSSEC_FAIL_NOZONE)
    return EDE_NO_ZONEKEY;
  else if (status & DNSSEC_FAIL_NOKEY)
    return EDE_NO_DNSKEY;
  else if (status & DNSSEC_FAIL_NODSSUP)
    return EDE_USUPDS;
  else if (status & DNSSEC_FAIL_NONSEC)
    return EDE_NO_NSEC;
  else if (status & DNSSEC_FAIL_INDET)
    return EDE_DNSSEC_IND;
  else if (status & DNSSEC_FAIL_NOSIG)
    return EDE_NO_RRSIG;
  else
    return EDE_UNSET;
}
#endif /* HAVE_DNSSEC */
