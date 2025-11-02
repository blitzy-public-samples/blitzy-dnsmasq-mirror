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
 * @file cache.c
 * @brief DNS cache with LRU eviction and negative caching
 *
 * DETAILED PURPOSE:
 * This file implements the DNS response cache subsystem for dnsmasq, providing
 * high-performance caching of DNS resource records with automatic TTL management
 * and memory-efficient storage. The cache uses a hash table with chaining for
 * O(1) average-case lookups, combined with a doubly-linked LRU (Least Recently
 * Used) list for efficient eviction of expired or least-used entries when the
 * cache reaches capacity.
 *
 * The implementation supports negative caching per RFC 2308 (NXDOMAIN and NODATA
 * responses), CNAME chain resolution with loop detection (maximum 10 hops), and
 * seamless integration with the DHCP subsystem for dynamic hostname-to-IP mapping.
 * Cache entries can originate from upstream DNS servers, local /etc/hosts file,
 * DHCP lease assignments, or authoritative local zones.
 *
 * KEY RESPONSIBILITIES:
 * - cache_init() - Initialize cache hash table and LRU list with configured size
 * - cache_insert() - Insert new DNS records with TTL-based expiry tracking
 * - cache_lookup() - Search cache by name/type/class with CNAME chain following
 * - cache_find_by_name() - Locate cache entries by domain name for iteration
 * - cache_find_by_addr() - Reverse lookup by IP address for PTR record handling
 * - cache_scan_free() - Garbage collection of expired entries and LRU eviction
 * - cache_hash() - Hash function using Barker code for uniform distribution
 * - cache_get_name() - Extract canonical name from cache record
 * - cache_enumerate() - Iterate through all cache entries for statistics/dump
 * - cache_make_stat() - Generate cache statistics for monitoring
 *
 * DEPENDENCIES:
 * - dnsmasq.h: struct crec (cache record), struct daemon (global config), union all_addr
 * - Uses blockdata.c for variable-length data storage (SRV targets, DNSSEC records)
 * - Called by forward.c for query/response caching during DNS forwarding pipeline
 * - Integrates with dhcp.c for dynamic hostname registration from DHCP leases
 * - Used by auth.c for authoritative zone record caching
 *
 * DATA STRUCTURES:
 * - struct crec (dnsmasq.h:465-477): Cache record containing name, address, TTL, flags
 *   - Hash chain pointers for collision resolution (hash_next)
 *   - LRU list pointers for eviction policy (next, prev)
 *   - Union for different address types (IPv4, IPv6, CNAME target, SRV data, DNSSEC keys)
 * - static struct crec *cache_head, *cache_tail: LRU list head and tail pointers
 * - static struct crec **hash_table: Array of hash bucket heads (power-of-two size)
 * - static int hash_size: Current hash table size (grows dynamically for large hosts files)
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP: Enables DHCP-specific cache operations (dhcp_spare freelist)
 * - HAVE_DNSSEC: Enables caching of DNSSEC records (DNSKEY, DS, RRSIG)
 * - SMALLDNAME: Inline name storage size for small domain names (avoids heap allocation)
 * - CACHESIZ (config.h): Default cache size if not specified (typically 150 records)
 *
 * THREADING/CONCURRENCY:
 * Single-process, event-driven architecture. All cache operations execute in the main
 * event loop thread. Cache modifications are atomic from the perspective of query
 * processing. No locking required as dnsmasq does not use multi-threading. Cache
 * expiry is checked lazily during lookups and via periodic cache_scan_free() calls.
 *
 * RFC COMPLIANCE:
 * - RFC 1035: DNS caching of A, AAAA, CNAME, PTR, MX, SRV, and other RR types
 * - RFC 2308: Negative caching of NXDOMAIN and NODATA responses with separate TTLs
 * - RFC 2181: TTL handling, authoritative answer caching, RRset consistency
 *
 * @see docs/DNS_CACHING.md for hash table implementation details
 * @see docs/ARCHITECTURE.md for cache subsystem integration
 * @see forward.c for DNS query forwarding and cache integration
 * @see dhcp.c for DHCP-to-cache hostname synchronization
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

static struct crec *cache_head = NULL, *cache_tail = NULL, **hash_table = NULL;
#ifdef HAVE_DHCP
static struct crec *dhcp_spare = NULL;
#endif
static struct crec *new_chain = NULL;
static int insert_error;
static union bigname *big_free = NULL;
static int bignames_left, hash_size;

static void make_non_terminals(struct crec *source);
static struct crec *really_insert(char *name, union all_addr *addr, unsigned short class,
				  time_t now,  unsigned long ttl, unsigned int flags);

/* type->string mapping: this is also used by the name-hash function as a mixing table. */
/* taken from https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml */
static const struct {
  unsigned int type;
  const char * const name;
} typestr[] = {
  { 1,   "A" }, /* a host address [RFC1035] */
  { 2,   "NS" }, /* an authoritative name server [RFC1035] */
  { 3,   "MD" }, /* a mail destination (OBSOLETE - use MX) [RFC1035] */
  { 4,   "MF" }, /* a mail forwarder (OBSOLETE - use MX) [RFC1035] */
  { 5,   "CNAME" }, /* the canonical name for an alias [RFC1035] */
  { 6,   "SOA" }, /* marks the start of a zone of authority [RFC1035] */
  { 7,   "MB" }, /* a mailbox domain name (EXPERIMENTAL) [RFC1035] */
  { 8,   "MG" }, /* a mail group member (EXPERIMENTAL) [RFC1035] */
  { 9,   "MR" }, /* a mail rename domain name (EXPERIMENTAL) [RFC1035] */
  { 10,  "NULL" }, /* a null RR (EXPERIMENTAL) [RFC1035] */
  { 11,  "WKS" }, /* a well known service description [RFC1035] */
  { 12,  "PTR" }, /* a domain name pointer [RFC1035] */
  { 13,  "HINFO" }, /* host information [RFC1035] */
  { 14,  "MINFO" }, /* mailbox or mail list information [RFC1035] */
  { 15,  "MX" }, /* mail exchange [RFC1035] */
  { 16,  "TXT" }, /* text strings [RFC1035] */
  { 17,  "RP" }, /* for Responsible Person [RFC1183] */
  { 18,  "AFSDB" }, /* for AFS Data Base location [RFC1183][RFC5864] */
  { 19,  "X25" }, /* for X.25 PSDN address [RFC1183] */
  { 20,  "ISDN" }, /* for ISDN address [RFC1183] */
  { 21,  "RT" }, /* for Route Through [RFC1183] */
  { 22,  "NSAP" }, /* for NSAP address, NSAP style A record [RFC1706] */
  { 23,  "NSAP_PTR" }, /* for domain name pointer, NSAP style [RFC1348][RFC1637][RFC1706] */
  { 24,  "SIG" }, /* for security signature [RFC2535][RFC2536][RFC2537][RFC2931][RFC3008][RFC3110][RFC3755][RFC4034] */
  { 25,  "KEY" }, /* for security key [RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110][RFC3755][RFC4034] */
  { 26,  "PX" }, /* X.400 mail mapping information [RFC2163] */
  { 27,  "GPOS" }, /* Geographical Position [RFC1712] */
  { 28,  "AAAA" }, /* IP6 Address [RFC3596] */
  { 29,  "LOC" }, /* Location Information [RFC1876] */
  { 30,  "NXT" }, /* Next Domain (OBSOLETE) [RFC2535][RFC3755] */
  { 31,  "EID" }, /* Endpoint Identifier [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt] 1995-06*/
  { 32,  "NIMLOC" }, /* Nimrod Locator [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt] 1995-06*/
  { 33,  "SRV" }, /* Server Selection [1][RFC2782] */
  { 34,  "ATMA" }, /* ATM Address [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.] */
  { 35,  "NAPTR" }, /* Naming Authority Pointer [RFC2168][RFC2915][RFC3403] */
  { 36,  "KX" }, /* Key Exchanger [RFC2230] */
  { 37,  "CERT" }, /* CERT [RFC4398] */
  { 38,  "A6" }, /* A6 (OBSOLETE - use AAAA) [RFC2874][RFC3226][RFC6563] */
  { 39,  "DNAME" }, /* DNAME [RFC6672] */
  { 40,  "SINK" }, /* SINK [Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink] 1997-11*/
  { 41,  "OPT" }, /* OPT [RFC3225][RFC6891] */
  { 42,  "APL" }, /* APL [RFC3123] */
  { 43,  "DS" }, /* Delegation Signer [RFC3658][RFC4034] */
  { 44,  "SSHFP" }, /* SSH Key Fingerprint [RFC4255] */
  { 45,  "IPSECKEY" }, /* IPSECKEY [RFC4025] */
  { 46,  "RRSIG" }, /* RRSIG [RFC3755][RFC4034] */
  { 47,  "NSEC" }, /* NSEC [RFC3755][RFC4034][RFC9077] */
  { 48,  "DNSKEY" }, /* DNSKEY [RFC3755][RFC4034] */
  { 49,  "DHCID" }, /* DHCID [RFC4701] */
  { 50,  "NSEC3" }, /* NSEC3 [RFC5155][RFC9077] */
  { 51,  "NSEC3PARAM" }, /* NSEC3PARAM [RFC5155] */
  { 52,  "TLSA" }, /* TLSA [RFC6698] */
  { 53,  "SMIMEA" }, /* S/MIME cert association [RFC8162] SMIMEA/smimea-completed-template 2015-12-01*/
  { 55,  "HIP" }, /* Host Identity Protocol [RFC8005] */
  { 56,  "NINFO" }, /* NINFO [Jim_Reid] NINFO/ninfo-completed-template 2008-01-21*/
  { 57,  "RKEY" }, /* RKEY [Jim_Reid] RKEY/rkey-completed-template 2008-01-21*/
  { 58,  "TALINK" }, /* Trust Anchor LINK [Wouter_Wijngaards] TALINK/talink-completed-template 2010-02-17*/
  { 59,  "CDS" }, /* Child DS [RFC7344] CDS/cds-completed-template 2011-06-06*/
  { 60,  "CDNSKEY" }, /* DNSKEY(s) the Child wants reflected in DS [RFC7344] 2014-06-16*/
  { 61,  "OPENPGPKEY" }, /* OpenPGP Key [RFC7929] OPENPGPKEY/openpgpkey-completed-template 2014-08-12*/
  { 62,  "CSYNC" }, /* Child-To-Parent Synchronization [RFC7477] 2015-01-27*/
  { 63,  "ZONEMD" }, /* Message Digest Over Zone Data [RFC8976] ZONEMD/zonemd-completed-template 2018-12-12*/
  { 64,  "SVCB" }, /* Service Binding [draft-ietf-dnsop-svcb-https-00] SVCB/svcb-completed-template 2020-06-30*/
  { 65,  "HTTPS" }, /* HTTPS Binding [draft-ietf-dnsop-svcb-https-00] HTTPS/https-completed-template 2020-06-30*/
  { 99,  "SPF" }, /* [RFC7208] */
  { 100, "UINFO" }, /* [IANA-Reserved] */
  { 101, "UID" }, /* [IANA-Reserved] */
  { 102, "GID" }, /* [IANA-Reserved] */
  { 103, "UNSPEC" }, /* [IANA-Reserved] */
  { 104, "NID" }, /* [RFC6742] ILNP/nid-completed-template */
  { 105, "L32" }, /* [RFC6742] ILNP/l32-completed-template */
  { 106, "L64" }, /* [RFC6742] ILNP/l64-completed-template */
  { 107, "LP" }, /* [RFC6742] ILNP/lp-completed-template */
  { 108, "EUI48" }, /* an EUI-48 address [RFC7043] EUI48/eui48-completed-template 2013-03-27*/
  { 109, "EUI64" }, /* an EUI-64 address [RFC7043] EUI64/eui64-completed-template 2013-03-27*/
  { 249, "TKEY" }, /* Transaction Key [RFC2930] */
  { 250, "TSIG" }, /* Transaction Signature [RFC8945] */
  { 251, "IXFR" }, /* incremental transfer [RFC1995] */
  { 252, "AXFR" }, /* transfer of an entire zone [RFC1035][RFC5936] */
  { 253, "MAILB" }, /* mailbox-related RRs (MB, MG or MR) [RFC1035] */
  { 254, "MAILA" }, /* mail agent RRs (OBSOLETE - see MX) [RFC1035] */
  { 255, "ANY" }, /* A request for some or all records the server has available [RFC1035][RFC6895][RFC8482] */
  { 256, "URI" }, /* URI [RFC7553] URI/uri-completed-template 2011-02-22*/
  { 257, "CAA" }, /* Certification Authority Restriction [RFC8659] CAA/caa-completed-template 2011-04-07*/
  { 258, "AVC" }, /* Application Visibility and Control [Wolfgang_Riedel] AVC/avc-completed-template 2016-02-26*/
  { 259, "DOA" }, /* Digital Object Architecture [draft-durand-doa-over-dns] DOA/doa-completed-template 2017-08-30*/
  { 260, "AMTRELAY" }, /* Automatic Multicast Tunneling Relay [RFC8777] AMTRELAY/amtrelay-completed-template 2019-02-06*/
  { 32768,  "TA" }, /* DNSSEC Trust Authorities [Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.] 2005-12-13*/
  { 32769,  "DLV" }, /* DNSSEC Lookaside Validation (OBSOLETE) [RFC8749][RFC4431] */
};

static void cache_free(struct crec *crecp);
static void cache_unlink(struct crec *crecp);
static void cache_link(struct crec *crecp);
static void rehash(int size);
static void cache_hash(struct crec *crecp);

/**
 * @brief Assign unique identifier to cache record if not already set
 *
 * @detailed
 * Allocates a unique unsigned integer ID to the given cache record for tracking
 * purposes. The UID is used primarily for CNAME validation to detect when a CNAME
 * target has been invalidated or changed. Each cache record can have only one UID
 * assigned during its lifetime; subsequent calls are no-ops.
 *
 * @param crecp Cache record to assign UID to (must not be NULL)
 *
 * @return None (void function, modifies crecp->uid in place)
 *
 * @note
 * UIDs are assigned sequentially from a static counter starting at 1. UID value
 * of 0 (UID_NONE) has special meaning indicating CNAME to interface name mapping.
 * If the counter wraps to 0, it is immediately incremented to 1 to avoid collision.
 *
 * @warning
 * Not thread-safe due to static uid counter. Assumes single-threaded execution
 * model of dnsmasq. Do not call from signal handlers.
 *
 * @see cache_insert() which calls this for newly created records
 * @see is_outdated_cname_pointer() which uses UIDs for CNAME validation
 *
 * EXAMPLE USAGE:
 * @code
 * struct crec *record = cache_insert("example.com", &addr, C_IN, now, 3600, F_IPV4);
 * next_uid(record);  // Assigns unique ID for CNAME tracking
 * @endcode
 *
 * SIDE EFFECTS:
 * Modifies static uid counter (increments on each new assignment). Modifies
 * crecp->uid field if it was previously UID_NONE.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
void next_uid(struct crec *crecp)
{
  static unsigned int uid = 0;

  if (crecp->uid == UID_NONE)
    {
      uid++;
  
      /* uid == 0 used to indicate CNAME to interface name. */
      if (uid == UID_NONE)
	uid++;
      
      crecp->uid = uid;
    }
}

/**
 * @brief Initialize DNS cache hash table and LRU list structures
 *
 * @detailed
 * Allocates and initializes the cache subsystem's data structures including the
 * cache record freelist (LRU list) and hash table for fast lookups. The cache
 * size is determined by daemon->cachesize configuration parameter. All cache
 * records are pre-allocated in a contiguous array and linked into the freelist
 * for efficient allocation during cache insertions.
 *
 * @return None (void function, initializes global cache state)
 *
 * @note
 * Cache size of 0 disables caching entirely. Default size is CACHESIZ (150) if
 * not configured. Also initializes bigname pool (10% of cache size) for long
 * domain names that don't fit in SMALLDNAME inline storage.
 *
 * @warning
 * Must be called exactly once during daemon initialization before any cache
 * operations. Calls safe_malloc() which terminates program on allocation failure.
 *
 * @see rehash() which creates the initial hash table sized appropriately
 * @see cache_link() which adds each record to the LRU freelist
 * @see cache.c:228 for bignames_left initialization (10% of cache size)
 *
 * EXAMPLE USAGE:
 * @code
 * daemon->cachesize = 1500;  // Configure cache size
 * cache_init();               // Initialize cache structures
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 caching requirements for DNS resource records.
 *
 * SIDE EFFECTS:
 * Allocates daemon->cachesize * sizeof(struct crec) bytes of memory. Initializes
 * global cache_head, cache_tail, hash_table, and hash_size variables. Modifies
 * bignames_left counter for long name allocation tracking.
 *
 * THREAD SAFETY:
 * Safe for single-threaded initialization. Must not be called concurrently.
 */
void cache_init(void)
{
  struct crec *crecp;
  int i;
 
  bignames_left = daemon->cachesize/10;
  
  if (daemon->cachesize > 0)
    {
      crecp = safe_malloc(daemon->cachesize*sizeof(struct crec));
      
      for (i=0; i < daemon->cachesize; i++, crecp++)
	{
	  cache_link(crecp);
	  crecp->flags = 0;
	  crecp->uid = UID_NONE;
	}
    }
  
  /* create initial hash table*/
  rehash(daemon->cachesize);
}

/**
 * @brief Expand hash table to accommodate growing cache size
 *
 * @detailed
 * Creates a new hash table array sized as a power of two (minimum 64 buckets)
 * that is approximately 10x smaller than the cache size (e.g., 1500 cache entries
 * would use ~256 buckets). All existing cache records are rehashed into the new
 * table. This function is called initially by cache_init() and subsequently by
 * hosts file parsing code every 1000 entries when loading large ad-block lists
 * (50,000+ entries) to maintain efficient O(1) lookup performance.
 *
 * @param size Target cache size to determine appropriate hash table dimensions
 *
 * @return None (void function, modifies global hash_table and hash_size)
 *
 * @note
 * Hash table size is always a power of two for efficient modulo operation using
 * bitwise AND (hash_size - 1). Initial allocation uses safe_malloc() which
 * terminates on failure; subsequent expansions use whine_malloc() and fail
 * gracefully if memory unavailable.
 *
 * @warning
 * If unable to allocate larger table, function returns without modifying existing
 * hash table. This is non-fatal - queries will still work but with degraded
 * performance due to longer hash chains. Not thread-safe due to global hash_table
 * pointer modification.
 *
 * @see hash_bucket() which computes hash bucket index using power-of-two size
 * @see cache_hash() which inserts records into hash chains
 * @see cache.c:336 for hash table sizing calculation (size/10 rounded to power of 2)
 *
 * EXAMPLE USAGE:
 * @code
 * // Expand hash table after loading 5000 hosts file entries
 * if (++hosts_loaded % 1000 == 0)
 *   rehash(hosts_loaded);
 * @endcode
 *
 * SIDE EFFECTS:
 * Allocates new hash table array, rehashes all existing records, frees old hash
 * table. Modifies global hash_table and hash_size variables. May log warning if
 * allocation fails.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
static void rehash(int size)
{
  struct crec **new, **old, *p, *tmp;
  int i, new_size, old_size;

  /* hash_size is a power of two. */
  for (new_size = 64; new_size < size/10; new_size = new_size << 1);
  
  /* must succeed in getting first instance, failure later is non-fatal */
  if (!hash_table)
    new = safe_malloc(new_size * sizeof(struct crec *));
  else if (new_size <= hash_size || !(new = whine_malloc(new_size * sizeof(struct crec *))))
    return;

  for(i = 0; i < new_size; i++)
    new[i] = NULL;

  old = hash_table;
  old_size = hash_size;
  hash_table = new;
  hash_size = new_size;
  
  if (old)
    {
      for (i = 0; i < old_size; i++)
	for (p = old[i]; p ; p = tmp)
	  {
	    tmp = p->hash_next;
	    cache_hash(p);
	  }
      free(old);
    }
}

/**
 * @brief Compute hash bucket pointer for domain name
 *
 * @detailed
 * Calculates hash value for given domain name using Barker code mixing (initial
 * value 017465 octal = 0x3D3D for minimum self-correlation). DNS type table is
 * used as mixing data to improve hash distribution. Name hashing is case-insensitive
 * (A-Z converted to a-z) to match DNS case-insensitivity per RFC 1035.
 *
 * @param name Domain name to hash (null-terminated C string, e.g., "example.com")
 *
 * @return Pointer to hash bucket head pointer (not the record itself, but &hash_table[index])
 *
 * @note
 * Returns pointer-to-pointer (**) to allow in-place modification of hash chain head.
 * Hash value is folded with XOR (val ^ (val >> 16)) and masked with (hash_size - 1)
 * to map to bucket index. Power-of-two hash_size makes masking equivalent to modulo.
 *
 * @warning
 * Does not validate name parameter. Caller must ensure name is valid null-terminated
 * string. Hash collisions are resolved by chaining (multiple records per bucket).
 *
 * @see cache_hash() which uses this to insert records into hash table
 * @see cache.c:366 for Barker code initial value selection
 * @see cache.c:374 for case-insensitive hashing (manual tolower to avoid locale issues)
 *
 * EXAMPLE USAGE:
 * @code
 * struct crec **bucket = hash_bucket("www.example.com");
 * // *bucket is the head of the hash chain for this name
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 1035: Case-insensitive domain name comparison for DNS.
 *
 * SIDE EFFECTS:
 * None. Pure function with no side effects.
 *
 * THREAD SAFETY:
 * Thread-safe for reads. Safe for dnsmasq's single-threaded model.
 */
static struct crec **hash_bucket(char *name)
{
  unsigned int c, val = 017465; /* Barker code - minimum self-correlation in cyclic shift */
  const unsigned char *mix_tab = (const unsigned char*)typestr; 

  while((c = (unsigned char) *name++))
    {
      /* don't use tolower and friends here - they may be messed up by LOCALE */
      if (c >= 'A' && c <= 'Z')
	c += 'a' - 'A';
      val = ((val << 7) | (val >> (32 - 7))) + (mix_tab[(val + c) & 0x3F] ^ c);
    } 
  
  /* hash_size is a power of two */
  return hash_table + ((val ^ (val >> 16)) & (hash_size - 1));
}

/**
 * @brief Insert cache record into hash table with ordering invariants
 *
 * @detailed
 * Adds cache record to appropriate hash bucket maintaining strict ordering:
 * F_REVERSE (PTR) records at chain head, F_IMMORTAL records at chain tail, all
 * others in middle. This ordering optimizes reverse lookups (PTR queries scan
 * only chain head) and garbage collection (skip immortal records at tail).
 *
 * @param crecp Cache record to insert (must have valid name and flags set)
 *
 * @return None (void function, modifies hash table in place)
 *
 * @note
 * Ordering invariant: [REVERSE records] -> [normal records] -> [IMMORTAL records].
 * F_REVERSE records (PTR for reverse DNS) are searched most frequently. F_IMMORTAL
 * records (from /etc/hosts) are never expired, so placing at tail speeds garbage
 * collection.
 *
 * @warning
 * Does not check for duplicate insertion. Caller must ensure record not already
 * in hash table. Assumes crecp name and flags are valid.
 *
 * @see hash_bucket() which computes insertion bucket
 * @see cache_get_name() which extracts name from cache record
 * @see cache.c:471-483 for insertion ordering algorithm
 *
 * EXAMPLE USAGE:
 * @code
 * struct crec *new_record = really_insert("example.com", &addr, C_IN, now, 3600, F_IPV4);
 * cache_hash(new_record);  // Insert into hash table
 * @endcode
 *
 * SIDE EFFECTS:
 * Modifies hash_table by prepending/inserting record into appropriate bucket chain.
 * Updates crecp->hash_next pointer to link into chain.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
static void cache_hash(struct crec *crecp)
{
  /* maintain an invariant that all entries with F_REVERSE set
     are at the start of the hash-chain  and all non-reverse
     immortal entries are at the end of the hash-chain.
     This allows reverse searches and garbage collection to be optimised */

  struct crec **up = hash_bucket(cache_get_name(crecp));

  if (!(crecp->flags & F_REVERSE))
    {
      while (*up && ((*up)->flags & F_REVERSE))
	up = &((*up)->hash_next); 
      
      if (crecp->flags & F_IMMORTAL)
	while (*up && !((*up)->flags & F_IMMORTAL))
	  up = &((*up)->hash_next);
    }
  crecp->hash_next = *up;
  *up = crecp;
}

/**
 * @brief Free variable-length blockdata associated with cache record
 *
 * @detailed
 * Releases heap-allocated blockdata for cache records containing variable-length
 * data such as SRV target names, DNSSEC DNSKEY/DS records. Non-negative (answer)
 * records only; negative cache entries have no associated blockdata.
 *
 * @param crecp Cache record whose blockdata should be freed
 *
 * @return None (void function, modifies blockdata freelists)
 *
 * @note
 * Only processes records without F_NEG flag (positive answers). SRV records store
 * target hostname in blockdata, DNSSEC records store key/signature data. Blockdata
 * uses reference-counted memory management for sharing between records.
 *
 * @warning
 * Must only be called when record is being removed from cache. Does not modify
 * crecp fields. Assumes blockdata pointers are valid or NULL.
 *
 * @see blockdata_free() in blockdata.c for actual deallocation
 * @see cache_free() which calls this before returning record to freelist
 * @see cache.c:491-496 for SRV and DNSSEC blockdata handling
 *
 * EXAMPLE USAGE:
 * @code
 * if (is_expired(now, old_record)) {
 *   cache_blockdata_free(old_record);
 *   cache_free(old_record);
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * Releases blockdata memory back to blockdata allocator. May consolidate free
 * blocks in blockdata.c freelists.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
static void cache_blockdata_free(struct crec *crecp)
{
  if (!(crecp->flags & F_NEG))
    {
      if (crecp->flags & F_SRV)
	blockdata_free(crecp->addr.srv.target);
#ifdef HAVE_DNSSEC
      else if (crecp->flags & F_DNSKEY)
	blockdata_free(crecp->addr.key.keydata);
      else if (crecp->flags & F_DS)
	blockdata_free(crecp->addr.ds.keydata);
#endif
    }
}

/**
 * @brief Return cache record to freelist (LRU tail)
 *
 * @detailed
 * Marks cache record as free by clearing F_FORWARD and F_REVERSE flags, invalidates
 * CNAME references by setting uid to UID_NONE, and appends record to LRU list tail
 * for reuse. Also reclaims bigname storage for long domain names and releases any
 * associated blockdata (SRV targets, DNSSEC records).
 *
 * @param crecp Cache record to free and return to available pool
 *
 * @return None (void function, modifies LRU list and freelists)
 *
 * @note
 * Record is not deallocated from memory; cache uses pre-allocated fixed-size pool.
 * Freeing makes record available for reuse by cache_scan_free() when inserting new
 * entries. F_BIGNAME flag is cleared and bigname returned to big_free list.
 *
 * @warning
 * Does not remove record from hash table. Caller must call cache_unlink() first
 * if record is in active use. Setting uid to UID_NONE invalidates CNAME pointers.
 *
 * @see cache_unlink() which removes record from LRU list before freeing
 * @see cache_blockdata_free() which releases variable-length data
 * @see cache.c:587-603 for freelist management and bigname reclamation
 *
 * EXAMPLE USAGE:
 * @code
 * if (is_expired(now, old_record)) {
 *   cache_unlink(old_record);   // Remove from LRU active list
 *   cache_free(old_record);     // Return to freelist
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * Appends record to cache_tail. Updates cache_head if list was empty. Returns
 * bigname to big_free list if F_BIGNAME set. Calls cache_blockdata_free() to
 * release SRV/DNSSEC data.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
static void cache_free(struct crec *crecp)
{
  crecp->flags &= ~F_FORWARD;
  crecp->flags &= ~F_REVERSE;
  crecp->uid = UID_NONE; /* invalidate CNAMES pointing to this. */

  if (cache_tail)
    cache_tail->next = crecp;
  else
    cache_head = crecp;
  crecp->prev = cache_tail;
  crecp->next = NULL;
  cache_tail = crecp;
  
  /* retrieve big name for further use. */
  if (crecp->flags & F_BIGNAME)
    {
      crecp->name.bname->next = big_free;
      big_free = crecp->name.bname;
      crecp->flags &= ~F_BIGNAME;
    }

  cache_blockdata_free(crecp);
}    

/**
 * @brief Insert cache record at LRU list head (most recently used position)
 *
 * @detailed
 * Prepends cache record to the head of the doubly-linked LRU list, marking it as
 * the most recently used entry. Records at list head are protected from eviction;
 * cache_scan_free() evicts from the tail (least recently used). Called during
 * cache initialization to build freelist and after cache hits to promote records.
 *
 * @param crecp Cache record to insert at list head
 *
 * @return None (void function, modifies LRU list in place)
 *
 * @note
 * Handles empty list case (initializes both cache_head and cache_tail). Does not
 * modify hash table; only affects LRU eviction ordering. Used for both fresh
 * allocations and LRU promotion of existing entries.
 *
 * @warning
 * Assumes crecp is not currently in list or has been unlinked first. Double-linking
 * same record without unlinking causes list corruption.
 *
 * @see cache_unlink() which must be called before relinking active record
 * @see cache_scan_free() which evicts from tail for LRU policy
 * @see cache.c:609-615 for LRU list head insertion logic
 *
 * EXAMPLE USAGE:
 * @code
 * struct crec *record = allocate_new_record();
 * cache_link(record);  // Add to head as most-recently-used
 * @endcode
 *
 * SIDE EFFECTS:
 * Modifies cache_head and possibly cache_tail. Updates prev/next pointers of
 * affected records.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
static void cache_link(struct crec *crecp)
{
  if (cache_head) /* check needed for init code */
    cache_head->prev = crecp;
  crecp->next = cache_head;
  crecp->prev = NULL;
  cache_head = crecp;
  if (!cache_tail)
    cache_tail = crecp;
}

/**
 * @brief Remove cache record from LRU list for promotion or eviction
 *
 * @detailed
 * Extracts cache record from its current position in the doubly-linked LRU list
 * without modifying hash table membership. Typically called before cache_link() to
 * promote record to head after cache hit, or before cache_free() when evicting
 * expired entries. Correctly handles removal from head, tail, or middle positions.
 *
 * @param crecp Cache record to remove from LRU list
 *
 * @return None (void function, modifies LRU list pointers only)
 *
 * @note
 * After unlinking, record's prev/next pointers are stale but not cleared. Caller
 * must either immediately relink via cache_link() or free via cache_free(). Does
 * not affect hash table membership - record remains searchable until cache_free().
 *
 * @warning
 * Record must currently be in LRU list. Unlinking non-member record may corrupt
 * list pointers. Does not clear crecp->prev/next; reuse requires cache_link().
 *
 * @see cache_link() which reinserts record after unlinking for promotion
 * @see cache_free() which should be called after unlink for eviction
 * @see cache.c:701-709 for doubly-linked list removal algorithm
 *
 * EXAMPLE USAGE:
 * @code
 * // Promote record to most-recently-used on cache hit
 * cache_unlink(hit_record);
 * cache_link(hit_record);  // Reinsert at head
 * @endcode
 *
 * SIDE EFFECTS:
 * Modifies cache_head if removing head, cache_tail if removing tail. Updates
 * prev/next pointers of adjacent records. Does not modify record itself except
 * leaving stale prev/next values.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
static void cache_unlink (struct crec *crecp)
{
  if (crecp->prev)
    crecp->prev->next = crecp->next;
  else
    cache_head = crecp->next;

  if (crecp->next)
    crecp->next->prev = crecp->prev;
  else
    cache_tail = crecp->prev;
}

/**
 * @brief Extract domain name from cache record
 *
 * @detailed
 * Returns pointer to domain name stored in cache record, handling three storage
 * methods: F_BIGNAME (heap-allocated for names > SMALLDNAME), F_NAMEP (pointer to
 * external string), or inline sname array (default for short names). This abstraction
 * allows callers to access name without knowing storage method.
 *
 * @param crecp Cache record to extract name from (must not be NULL)
 *
 * @return Pointer to null-terminated domain name string (never NULL for valid record)
 *
 * @note
 * Returned pointer may become invalid if cache record is freed or modified. Caller
 * should not cache pointer across cache operations. SMALLDNAME is typically 50 bytes;
 * longer names require bigname heap allocation.
 *
 * @warning
 * Returned string must not be modified. Lifetime tied to cache record lifetime.
 * Invalid if record is freed or reallocated.
 *
 * @see cache.c:754-759 for name storage method selection
 * @see hash_bucket() which uses this to compute hash for record
 * @see SMALLDNAME constant in dnsmasq.h for inline name size threshold
 *
 * EXAMPLE USAGE:
 * @code
 * struct crec *record = cache_find_by_name(NULL, "example.com", now, F_IPV4);
 * if (record)
 *   my_syslog(LOG_INFO, "Found %s", cache_get_name(record));
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 1035: Domain names up to 255 characters supported.
 *
 * SIDE EFFECTS:
 * None. Read-only access to cache record name field.
 *
 * THREAD SAFETY:
 * Thread-safe for reads while record is valid. Safe for dnsmasq's single-threaded model.
 */
char *cache_get_name(struct crec *crecp)
{
  if (crecp->flags & F_BIGNAME)
    return crecp->name.bname->name;
  else if (crecp->flags & F_NAMEP) 
    return crecp->name.namep;
  
  return crecp->name.sname;
}

/**
 * @brief Extract CNAME target from cache record
 *
 * @detailed
 * Returns canonical name (target) for CNAME records. Handles two CNAME storage modes:
 * is_name_ptr true means target is direct string pointer; false means target is
 * pointer to another cache record whose name is the target. Recursively resolves
 * indirect cache record references.
 *
 * @param crecp CNAME cache record (must have F_CNAME flag set)
 *
 * @return Pointer to target domain name string
 *
 * @note
 * For indirect targets (cache record pointers), validates target record is still
 * valid using UID matching. Outdated pointers may return incorrect results if
 * target record has been reused.
 *
 * @warning
 * Assumes crecp is a CNAME record. Results undefined for non-CNAME records. Returned
 * pointer lifetime tied to target record lifetime.
 *
 * @see cache_get_name() which extracts name from indirect cache record targets
 * @see is_outdated_cname_pointer() which validates CNAME target record currency
 * @see cache.c:764-767 for CNAME target resolution logic
 *
 * EXAMPLE USAGE:
 * @code
 * if (record->flags & F_CNAME) {
 *   char *target = cache_get_cname_target(record);
 *   my_syslog(LOG_INFO, "CNAME points to %s", target);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 1035 Section 3.3.1: CNAME RR format with target name (CNAME RDATA).
 *
 * SIDE EFFECTS:
 * None for direct name pointers. May call cache_get_name() for indirect references.
 *
 * THREAD SAFETY:
 * Thread-safe for reads. Safe for dnsmasq's single-threaded event loop model.
 */
char *cache_get_cname_target(struct crec *crecp)
{
  if (crecp->addr.cname.is_name_ptr)
     return crecp->addr.cname.target.name;
  else
    return cache_get_name(crecp->addr.cname.target.cache);
}

/**
 * @brief Iterate through all cache records in hash table
 *
 * @detailed
 * Provides stateful iteration over entire cache for statistics generation or dumps.
 * Traverses hash table bucket-by-bucket, following hash chains within each bucket.
 * Uses static variables to maintain iteration state between calls. Call with init=1
 * to start iteration, then repeatedly with init=0 until returns NULL.
 *
 * @param init Set to 1 to initialize/restart iteration, 0 to continue iteration
 *
 * @return Next cache record in iteration, or NULL when iteration complete
 *
 * @note
 * Iteration order is hash-table-dependent (not LRU order or insertion order). Returns
 * all records regardless of expired/active status. Caller must filter as needed. Not
 * reentrant - only one iteration can be active at a time due to static state.
 *
 * @warning
 * Do not modify cache structure during iteration (no insert/delete/rehash). Modifying
 * iterated record is safe. Not thread-safe due to static bucket/cache variables.
 *
 * @see cache_make_stat() in forward.c which uses this for cache statistics
 * @see cache_dump() which uses this for SIGUSR1 cache dumps
 * @see cache.c:862-877 for hash table iteration algorithm
 *
 * EXAMPLE USAGE:
 * @code
 * struct crec *record;
 * for (record = cache_enumerate(1); record; record = cache_enumerate(0)) {
 *   printf("%s\n", cache_get_name(record));
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * Modifies static bucket and cache variables to track iteration state.
 *
 * THREAD SAFETY:
 * Not thread-safe (static state). Not reentrant. Safe for dnsmasq's single-threaded
 * event loop where only one iteration occurs at a time.
 */

struct crec *cache_enumerate(int init)
{
  static int bucket;
  static struct crec *cache;

  if (init)
    {
      bucket = 0;
      cache = NULL;
    }
  else if (cache && cache->hash_next)
    cache = cache->hash_next;
  else
    {
       cache = NULL; 
       while (bucket < hash_size)
	 if ((cache = hash_table[bucket++]))
	   break;
    }
  
  return cache;
}

/**
 * @brief Check if CNAME cache entry's target pointer is stale
 * 
 * @detailed Detects CNAME records with outdated cache pointers to target records. Returns 0 (valid)
 * if not a CNAME, if using name pointer (is_name_ptr), or if target cache pointer valid and UIDs
 * match. Returns 1 (outdated) if target pointer exists but UIDs mismatch, indicating target was
 * freed and reallocated. Special case: ignores UID mismatch if target reused as DS/DNSKEY (uid
 * overloaded for class). Used by cache_scan_free() to identify broken CNAME chains for cleanup.
 * 
 * @param crecp Cache record to check (CNAME or other)
 * 
 * @return int 1 if outdated CNAME pointer (target freed/reused), 0 if valid or not applicable
 * @retval 0 Not a CNAME, uses name pointer, or target pointer valid (matching UIDs)
 * @retval 1 CNAME with outdated cache pointer (target freed, UID mismatch)
 * 
 * @note Returns 0 (valid) for non-CNAME records
 * @note Returns 0 if crecp->addr.cname.is_name_ptr (using string name, not cache pointer)
 * @note Returns 0 if target pointer NULL (not yet resolved)
 * @note Returns 0 if target reused as DS/DNSKEY (uid repurposed for class)
 * @note UID comparison detects target reallocation: if UIDs differ, target was freed and slot reused
 * 
 * @see cache_scan_free() caller for removing outdated CNAMEs
 * @see struct crec addr.cname.target.cache for CNAME target pointer
 * @see crecp->uid and target->uid for reallocation detection
 * 
 * EXAMPLE USAGE:
 * @code
 * if (is_outdated_cname_pointer(crecp))
 *   // CNAME target was freed, remove this CNAME too
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal cache integrity checking)
 * 
 * SIDE EFFECTS: None (read-only predicate)
 * 
 * THREAD SAFETY: Thread-safe (read-only)
 */
static int is_outdated_cname_pointer(struct crec *crecp)
{
  if (!(crecp->flags & F_CNAME) || crecp->addr.cname.is_name_ptr)
    return 0;
  
  /* NB. record may be reused as DS or DNSKEY, where uid is 
     overloaded for something completely different */
  if (crecp->addr.cname.target.cache && 
      !(crecp->addr.cname.target.cache->flags & (F_DNSKEY | F_DS)) &&
      crecp->addr.cname.uid == crecp->addr.cname.target.cache->uid)
    return 0;
  
  return 1;
}

/**
 * @brief Check if cache record has expired based on TTL
 * 
 * @detailed Compares current time against cache record's Time To Die (TTD) field. Returns 0 (valid)
 * if record is immortal (F_IMMORTAL flag) or TTD > now. Returns 1 (expired) if TTD <= now.
 * Used throughout cache code to filter expired entries during lookups and maintenance scans.
 * TTD stored as absolute time (seconds since epoch), calculated as insertion_time + TTL.
 * 
 * @param now Current time in seconds since epoch (from time(NULL))
 * @param crecp Cache record to check for expiry
 * 
 * @return int 1 if record expired (now >= ttd), 0 if valid (F_IMMORTAL or now < ttd)
 * @retval 0 Record valid: F_IMMORTAL or TTD in future
 * @retval 1 Record expired: now >= TTD and not immortal
 * 
 * @note F_IMMORTAL records never expire (from /etc/hosts, static DHCP, etc.)
 * @note TTD is absolute time (epoch seconds), not relative TTL
 * @note Uses difftime() for precise floating-point comparison
 * @note Called extensively during cache lookups and maintenance
 * 
 * @see crec->ttd for Time To Die field (absolute expiry time)
 * @see F_IMMORTAL flag for non-expiring entries
 * @see cache_scan_free() for expiry-based cleanup
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = time(NULL);
 * if (is_expired(now, cache_entry))
 *   // Entry past TTL, should be evicted
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DNS TTL semantics per RFC 1035 Section 3.2.1
 * 
 * SIDE EFFECTS: None (read-only predicate)
 * 
 * THREAD SAFETY: Thread-safe (read-only)
 */
static int is_expired(time_t now, struct crec *crecp)
{
  if (crecp->flags & F_IMMORTAL)
    return 0;

  if (difftime(now, crecp->ttd) < 0)
    return 0;
  
  return 1;
}

/**
 * @brief Scan cache for expired/conflicting entries and free them
 * 
 * @detailed Multi-purpose cache maintenance function handling expiry and conflict resolution.
 * Three operating modes based on flags: 1) F_FORWARD: scan single hash bucket for name conflicts
 * and expired entries, 2) F_REVERSE: scan entire cache for address conflicts and expired entries,
 * 3) flags==0: scan entire cache for expired entries only. Never deletes F_HOSTS/F_DHCP/F_CONFIG
 * (static) entries. Returns existing static entry if found during F_FORWARD scan (conflict detected).
 * If freeing CNAME target (uid != UID_NONE), returns crec and uid via output parameters for reuse
 * by really_insert() to preserve existing CNAMEs pointing to that target. Takes advantage of hash
 * chain ordering (reverse, other, immortal) to optimize scanning.
 * 
 * @param name Domain name for F_FORWARD mode (hash bucket selector), NULL for other modes
 * @param addr IP address for F_REVERSE mode (conflict detection), NULL for other modes
 * @param class DNS class (currently unused, for future DNSSEC class-sensitive deletion)
 * @param now Current time for expiry checking (seconds since epoch)
 * @param flags Operating mode: F_FORWARD (name scan), F_REVERSE (addr scan), 0 (expiry only)
 * @param target_crec Output parameter: receives freed CNAME target crec for reuse, NULL if not needed
 * @param target_uid Output parameter: receives freed CNAME target UID for preservation, NULL if not needed
 * 
 * @return struct crec * if F_FORWARD mode found static (F_HOSTS/F_DHCP/F_CONFIG) entry, NULL otherwise
 * @retval struct crec * Conflict with static entry (F_HOSTS | F_DHCP | F_CONFIG) found
 * @retval NULL No static conflict found, or flags not F_FORWARD
 * 
 * @note Never deletes F_HOSTS, F_DHCP, or F_CONFIG entries (static configuration)
 * @note In F_FORWARD mode, scans only hash_bucket(name), not entire cache
 * @note In F_REVERSE or flags==0 mode, scans all hash_size buckets
 * @note DNSSEC records (F_DS, F_DNSKEY) co-exist with CNAMEs, not deleted for CNAME insertion
 * @note DNSSEC deletion is class-sensitive (crecp->uid == class match required)
 * @note Hash chain ordering optimization: stops at first non-reverse immortal entry
 * @note If target_crec and target_uid provided, returns info for CNAME target reuse
 * 
 * @warning Modifies cache structure, removes entries from hash chains and LRU list
 * @warning Caller must handle returned static entry conflict appropriately
 * 
 * @see really_insert() for caller using target_crec/target_uid for CNAME preservation
 * @see is_expired() for TTL checking
 * @see is_outdated_cname_pointer() for stale CNAME detection
 * @see cache_unlink() and cache_free() for entry deletion
 * 
 * EXAMPLE USAGE:
 * @code
 * // Check for conflicts before inserting "example.com" A record
 * struct crec *conflict = cache_scan_free("example.com", NULL, C_IN, time(NULL), 
 *                                         F_IPV4 | F_FORWARD, NULL, NULL);
 * if (conflict && (conflict->flags & F_HOSTS))
 *   // Conflict with /etc/hosts entry, abort insertion
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DNS caching expiry per RFC 1035 TTL semantics
 * 
 * SIDE EFFECTS:
 * - Removes expired entries from hash table and LRU list
 * - Frees removed entries via cache_free()
 * - May set *target_crec and *target_uid for CNAME target reuse
 * - Scans entire cache if F_REVERSE or flags==0
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
static struct crec *cache_scan_free(char *name, union all_addr *addr, unsigned short class, time_t now,
				    unsigned int flags, struct crec **target_crec, unsigned int *target_uid)
{
  /* Scan and remove old entries.
     If (flags & F_FORWARD) then remove any forward entries for name and any expired
     entries but only in the same hash bucket as name.
     If (flags & F_REVERSE) then remove any reverse entries for addr and any expired
     entries in the whole cache.
     If (flags == 0) remove any expired entries in the whole cache. 

     In the flags & F_FORWARD case, the return code is valid, and returns a non-NULL pointer
     to a cache entry if the name exists in the cache as a HOSTS or DHCP entry (these are never deleted)

     We take advantage of the fact that hash chains have stuff in the order <reverse>,<other>,<immortal>
     so that when we hit an entry which isn't reverse and is immortal, we're done. 

     If we free a crec which is a CNAME target, return the entry and uid in target_crec and target_uid.
     This entry will get re-used with the same name, to preserve CNAMEs. */
 
  struct crec *crecp, **up;

  (void)class;
  
  if (flags & F_FORWARD)
    {
      for (up = hash_bucket(name), crecp = *up; crecp; crecp = crecp->hash_next)
	{
	  if ((crecp->flags & F_FORWARD) && hostname_isequal(cache_get_name(crecp), name))
	    {
	      /* Don't delete DNSSEC in favour of a CNAME, they can co-exist */
	      if ((flags & crecp->flags & (F_IPV4 | F_IPV6 | F_SRV | F_NXDOMAIN)) || 
		  (((crecp->flags | flags) & F_CNAME) && !(crecp->flags & (F_DNSKEY | F_DS))))
		{
		  if (crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG))
		    return crecp;
		  *up = crecp->hash_next;
		  /* If this record is for the name we're inserting and is the target
		     of a CNAME record. Make the new record for the same name, in the same
		     crec, with the same uid to avoid breaking the existing CNAME. */
		  if (crecp->uid != UID_NONE)
		    {
		      if (target_crec)
			*target_crec = crecp;
		      if (target_uid)
			*target_uid = crecp->uid;
		    }
		  cache_unlink(crecp);
		  cache_free(crecp);
		  continue;
		}
	      
#ifdef HAVE_DNSSEC
	      /* Deletion has to be class-sensitive for DS and DNSKEY */
	      if ((flags & crecp->flags & (F_DNSKEY | F_DS)) && crecp->uid == class)
		{
		  if (crecp->flags & F_CONFIG)
		    return crecp;
		  *up = crecp->hash_next;
		  cache_unlink(crecp);
		  cache_free(crecp);
		  continue;
		}
#endif
	    }

	  if (is_expired(now, crecp) || is_outdated_cname_pointer(crecp))
	    { 
	      *up = crecp->hash_next;
	      if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		{
		  cache_unlink(crecp);
		  cache_free(crecp);
		}
	      continue;
	    } 
	  
	  up = &crecp->hash_next;
	}
    }
  else
    {
      int i;
      int addrlen = (flags & F_IPV6) ? IN6ADDRSZ : INADDRSZ;

      for (i = 0; i < hash_size; i++)
	for (crecp = hash_table[i], up = &hash_table[i]; 
	     crecp && ((crecp->flags & F_REVERSE) || !(crecp->flags & F_IMMORTAL));
	     crecp = crecp->hash_next)
	  if (is_expired(now, crecp))
	    {
	      *up = crecp->hash_next;
	      if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		{ 
		  cache_unlink(crecp);
		  cache_free(crecp);
		}
	    }
	  else if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) &&
		   (flags & crecp->flags & F_REVERSE) && 
		   (flags & crecp->flags & (F_IPV4 | F_IPV6)) &&
		   addr && memcmp(&crecp->addr, addr, addrlen) == 0)
	    {
	      *up = crecp->hash_next;
	      cache_unlink(crecp);
	      cache_free(crecp);
	    }
	  else
	    up = &crecp->hash_next;
    }
  
  return NULL;
}

/* Note: The normal calling sequence is
   cache_start_insert
   cache_insert * n
   cache_end_insert

   but an abort can cause the cache_end_insert to be missed 
   in which can the next cache_start_insert cleans things up. */

/**
 * @brief Begin transactional cache insertion sequence
 *
 * @detailed
 * Initiates a multi-record cache insertion transaction. Cleans up any uncommitted
 * records from previous transaction that was aborted (e.g., due to SERVFAIL response).
 * Must be paired with cache_end_insert() to commit records, or records remain in
 * limbo on new_chain list. Typical sequence: cache_start_insert(), multiple
 * cache_insert() calls, cache_end_insert().
 *
 * @return None (void function, initializes transaction state)
 *
 * @note
 * Transactional model prevents partial cache updates from malformed or incomplete
 * responses. If cache_end_insert() never called (error path), subsequent
 * cache_start_insert() will clean up uncommitted records. insert_error flag tracks
 * whether transaction should be aborted.
 *
 * @warning
 * Not reentrant. Only one transaction can be active at a time. Calling
 * cache_start_insert() twice without intervening cache_end_insert() loses first
 * transaction's records.
 *
 * @see cache_insert() which adds records to transaction
 * @see cache_end_insert() which commits transaction to cache
 * @see cache.c:1072-1078 for uncommitted record cleanup
 *
 * EXAMPLE USAGE:
 * @code
 * cache_start_insert();
 * cache_insert("example.com", &addr1, C_IN, now, 3600, F_IPV4);
 * cache_insert("www.example.com", &addr2, C_IN, now, 3600, F_CNAME);
 * cache_end_insert();  // Commit both records
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 2181 Section 5.2: RRsets must be cached atomically.
 *
 * SIDE EFFECTS:
 * Frees any records on new_chain list. Clears new_chain and insert_error flags.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
void cache_start_insert(void)
{
  /* Free any entries which didn't get committed during the last
     insert due to error.
  */
  while (new_chain)
    {
      struct crec *tmp = new_chain->next;
      cache_free(new_chain);
      new_chain = tmp;
    }
  new_chain = NULL;
  insert_error = 0;
}

/**
 * @brief Insert DNS resource record into cache with TTL management
 *
 * @detailed
 * Creates new cache entry for DNS RR with specified name, address, class, and TTL.
 * Applies configured min/max TTL constraints except for DNSSEC records which use
 * DNSSEC_MIN_TTL floor. Records are added to transaction started by cache_start_insert()
 * and committed by cache_end_insert(). Supports IPv4 (F_IPV4), IPv6 (F_IPV6), CNAME
 * (F_CNAME), negative (F_NEG), DNSSEC (F_DNSKEY/F_DS), and other RR types.
 *
 * @param name Domain name for record (e.g., "example.com", null-terminated)
 * @param addr Address data (IPv4/IPv6 in_addr/in6_addr, or CNAME target, or NULL for NEG)
 * @param class DNS class (typically C_IN = 1 for Internet)
 * @param now Current time (seconds since epoch) for TTL expiration calculation
 * @param ttl Time-to-live in seconds before record expires
 * @param flags Record type and properties (F_IPV4, F_IPV6, F_CNAME, F_NEG, F_DNSSEC, etc.)
 *
 * @return Newly created cache record, or NULL on error (out of memory, insert_error set)
 *
 * @note
 * TTL constraints: DNSSEC records use DNSSEC_MIN_TTL (120s) minimum. Other records
 * respect daemon->min_cache_ttl and daemon->max_cache_ttl if configured. Zero TTL
 * allowed for non-DNSSEC records but discouraged per RFC 2181.
 *
 * @warning
 * Must be called between cache_start_insert() and cache_end_insert(). Record not
 * visible in cache until cache_end_insert() commits transaction. Returns NULL if
 * previous insert in transaction failed (insert_error flag set).
 *
 * @see cache_start_insert() which begins transaction
 * @see cache_end_insert() which commits all inserted records
 * @see really_insert() which performs actual insertion logic
 * @see cache.c:1139-1148 for TTL clamping logic
 *
 * EXAMPLE USAGE:
 * @code
 * cache_start_insert();
 * struct crec *rec = cache_insert("www.example.com", &ipv4_addr, C_IN, time(NULL), 3600, F_IPV4);
 * if (rec)
 *   cache_end_insert();
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 1035: DNS RR caching. RFC 2181: TTL handling and minimum values. RFC 2308: Negative caching.
 *
 * SIDE EFFECTS:
 * Allocates cache record, may evict LRU entries if cache full. Calls really_insert()
 * which modifies cache hash table and LRU list. May allocate bigname for long names.
 *
 * THREAD SAFETY:
 * Not thread-safe. Safe for dnsmasq's single-threaded event loop model.
 */
struct crec *cache_insert(char *name, union all_addr *addr, unsigned short class,
			  time_t now,  unsigned long ttl, unsigned int flags)
{
#ifdef HAVE_DNSSEC
  if (flags & (F_DNSKEY | F_DS)) 
    {
      /* The DNSSEC validation process works by getting needed records into the
	 cache, then retrying the validation until they are all in place.
	 This can be messed up by very short TTLs, and _really_ messed up by
	 zero TTLs, so we force the TTL to be at least long enough to do a validation.
	 Ideally, we should use some kind of reference counting so that records are
	 locked until the validation that asked for them is complete, but this
	 is much easier, and just as effective. */
      if (ttl < DNSSEC_MIN_TTL)
	ttl = DNSSEC_MIN_TTL;
    }
  else
#endif
    {
      if (daemon->max_cache_ttl != 0 && daemon->max_cache_ttl < ttl)
	ttl = daemon->max_cache_ttl;
      if (daemon->min_cache_ttl != 0 && daemon->min_cache_ttl > ttl)
	ttl = daemon->min_cache_ttl;
    }	
  
  return really_insert(name, addr, class, now, ttl, flags);
}


/**
 * @brief Internal function to insert DNS record into cache with LRU eviction
 * 
 * @detailed Core cache insertion logic called by cache_insert(). Manages LRU eviction, conflict
 * resolution, bigname allocation, and cache entry reuse. Refuses zero-TTL records. Scans for
 * expired entries and conflicts via cache_scan_free(). If conflict with F_HOSTS/F_CONFIG/F_DHCP
 * entry detected and addresses match, silently succeeds (duplicate). If addresses differ, fails
 * with insert_error=1 to prevent overriding static configuration. Allocates from LRU tail,
 * triggering eviction if cache full. For names >SMALLDNAME-1, allocates bigname from big_free
 * list or whine_malloc(). Preserves CNAME target UIDs across replacement. Adds new entry to
 * new_chain for batch commit by cache_end_insert(). Sets TTD = now + ttl.
 * 
 * @param name Domain name (null-terminated, copied into cache), NULL for reverse-only
 * @param addr IP address (union all_addr, copied), NULL for CNAME/non-address records
 * @param class DNS class (C_IN for Internet), used as DNSSEC record key if F_DS/F_DNSKEY
 * @param now Current time (seconds since epoch) for TTL calculation
 * @param ttl Time To Live in seconds (0 = reject insertion with insert_error=1)
 * @param flags Record type flags (F_IPV4, F_IPV6, F_FORWARD, F_REVERSE, F_CNAME, F_DS, etc.)
 * 
 * @return Pointer to inserted cache record (struct crec *), or NULL if insertion failed
 * @retval struct crec * Successful insertion, entry added to new_chain
 * @retval NULL if ttl==0, insert_error set, cache full, malloc failure, or conflict
 * 
 * @note Sets global insert_error=1 on failure, causing cache_insert() to abort transaction
 * @note Rejects zero-TTL records (ttl==0) as uncacheable
 * @note Silently succeeds (returns existing entry) if duplicate of F_HOSTS/F_CONFIG with same address
 * @note Fails if conflicting with F_HOSTS/F_CONFIG/F_DHCP with different address
 * @note Allocates bigname for names longer than SMALLDNAME-1 (63 chars)
 * @note Decrements bignames_left quota if allocating new bigname (unless F_DS/F_DNSKEY)
 * @note Preserves CNAME target UID when replacing CNAME target entry
 * @note Unlinks from LRU before modification, adds to new_chain instead of direct re-link
 * @note Increments daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED] if evicting live entry
 * 
 * @warning Not thread-safe, modifies global insert_error, big_free, bignames_left, new_chain
 * @warning insert_error sticky flag persists until cache_end_insert() clears it
 * @warning Infinite loop protection: logs "Internal error in cache" if freeing doesn't create space
 * 
 * @see cache_insert() public wrapper for insertion
 * @see cache_scan_free() for conflict/expiry checking and eviction
 * @see cache_end_insert() for committing new_chain entries
 * @see SMALLDNAME constant for name length threshold (64 bytes typically)
 * @see union bigname for long name storage
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called internally by cache_insert(), not directly by external code
 * struct crec *entry = really_insert("example.com", &addr, C_IN, time(NULL), 3600, F_IPV4 | F_FORWARD);
 * if (entry == NULL)
 *   // Insertion failed, insert_error=1, transaction will abort
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DNS caching per RFC 1035, respects TTL
 * 
 * SIDE EFFECTS:
 * - Sets insert_error=1 on failure (sticky until cache_end_insert)
 * - Allocates bigname from big_free or malloc if name long
 * - Decrements bignames_left quota
 * - Unlinks entry from LRU list
 * - Adds entry to new_chain list
 * - May trigger cache_scan_free evicting other entries
 * - Increments METRIC_DNS_CACHE_LIVE_FREED if evicting live entry
 * - Logs "Internal error in cache" if infinite loop detected
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
static struct crec *really_insert(char *name, union all_addr *addr, unsigned short class,
				  time_t now,  unsigned long ttl, unsigned int flags)
{
  struct crec *new, *target_crec = NULL;
  union bigname *big_name = NULL;
  int freed_all = flags & F_REVERSE;
  int free_avail = 0;
  unsigned int target_uid;
  
  /* if previous insertion failed give up now. */
  if (insert_error)
    return NULL;

  /* we don't cache zero-TTL records. */
  if (ttl == 0)
    {
      insert_error = 1;
      return NULL;
    }
  
  /* First remove any expired entries and entries for the name/address we
     are currently inserting. */
  if ((new = cache_scan_free(name, addr, class, now, flags, &target_crec, &target_uid)))
    {
      /* We're trying to insert a record over one from 
	 /etc/hosts or DHCP, or other config. If the 
	 existing record is for an A or AAAA or CNAME and
	 the record we're trying to insert is the same, 
	 just drop the insert, but don't error the whole process. */
      if ((flags & (F_IPV4 | F_IPV6)) && (flags & F_FORWARD) && addr)
	{
	  if ((flags & F_IPV4) && (new->flags & F_IPV4) &&
	      new->addr.addr4.s_addr == addr->addr4.s_addr)
	    return new;
	  else if ((flags & F_IPV6) && (new->flags & F_IPV6) &&
		   IN6_ARE_ADDR_EQUAL(&new->addr.addr6, &addr->addr6))
	    return new;
	}

      insert_error = 1;
      return NULL;
    }
  
  /* Now get a cache entry from the end of the LRU list */
  if (!target_crec)
    while (1) {
      if (!(new = cache_tail)) /* no entries left - cache is too small, bail */
	{
	  insert_error = 1;
	  return NULL;
	}
      
      /* Free entry at end of LRU list, use it. */
      if (!(new->flags & (F_FORWARD | F_REVERSE)))
	break;

      /* End of LRU list is still in use: if we didn't scan all the hash
	 chains for expired entries do that now. If we already tried that
	 then it's time to start spilling things. */
      
      /* If free_avail set, we believe that an entry has been freed.
	 Bugs have been known to make this not true, resulting in
	 a tight loop here. If that happens, abandon the
	 insert. Once in this state, all inserts will probably fail. */
      if (free_avail)
	{
	  static int warned = 0;
	  if (!warned)
	    {
	      my_syslog(LOG_ERR, _("Internal error in cache."));
	      warned = 1;
	    }
	  insert_error = 1;
	  return NULL;
	}
      
      if (freed_all)
	{
	  /* For DNSSEC records, uid holds class. */
	  free_avail = 1; /* Must be free space now. */
	  cache_scan_free(cache_get_name(new), &new->addr, new->uid, now, new->flags, NULL, NULL);
	  daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]++;
	}
      else
	{
	  cache_scan_free(NULL, NULL, class, now, 0, NULL, NULL);
	  freed_all = 1;
	}
    }
      
  /* Check if we need to and can allocate extra memory for a long name.
     If that fails, give up now, always succeed for DNSSEC records. */
  if (name && (strlen(name) > SMALLDNAME-1))
    {
      if (big_free)
	{ 
	  big_name = big_free;
	  big_free = big_free->next;
	}
      else if ((bignames_left == 0 && !(flags & (F_DS | F_DNSKEY))) ||
	       !(big_name = (union bigname *)whine_malloc(sizeof(union bigname))))
	{
	  insert_error = 1;
	  return NULL;
	}
      else if (bignames_left != 0)
	bignames_left--;
      
    }

  /* If we freed a cache entry for our name which was a CNAME target, use that.
     and preserve the uid, so that existing CNAMES are not broken. */
  if (target_crec)
    {
      new = target_crec;
      new->uid = target_uid;
    }
  
  /* Got the rest: finally grab entry. */
  cache_unlink(new);
  
  new->flags = flags;
  if (big_name)
    {
      new->name.bname = big_name;
      new->flags |= F_BIGNAME;
    }

  if (name)
    strcpy(cache_get_name(new), name);
  else
    *cache_get_name(new) = 0;

#ifdef HAVE_DNSSEC
  if (flags & (F_DS | F_DNSKEY))
    new->uid = class;
#endif

  if (addr)
    new->addr = *addr;	

  new->ttd = now + (time_t)ttl;
  new->next = new_chain;
  new_chain = new;

  return new;
}

/**
 * @brief Commit new cache entries created during insertion transaction
 * 
 * @detailed Finalizes a cache insertion transaction started by cache_start_insert().
 * Iterates through the new_chain list, hashes and links valid entries into the cache,
 * drops CNAME records that didn't find their targets, and sends cache entries to the
 * master process via pipe if running as child process (daemon->pipe_to_parent != -1).
 * Marshals cache entries including name, TTL, flags, and type-specific data (addresses,
 * SRV targets, DNSKEY/DS records with blockdata).
 * 
 * @return void
 * 
 * @note Must be called after cache_start_insert() even if no inserts performed
 * @note Clears new_chain list and insert_error flag
 * @note If insert_error is set, discards all pending insertions without committing
 * @note Increments daemon->metrics[METRIC_DNS_CACHE_INSERTED] for each committed entry
 * 
 * @warning Not thread-safe, uses global new_chain and insert_error state
 * 
 * @see cache_start_insert() for transaction initialization
 * @see cache_insert() for adding entries during transaction
 * @see cache_recv_insert() for receiving marshalled entries in master process
 * 
 * EXAMPLE USAGE:
 * @code
 * cache_start_insert();
 * cache_insert("example.com", &addr, time(NULL), 3600, F_IPV4 | F_FORWARD);
 * cache_insert("www.example.com", &addr, time(NULL), 3600, F_IPV4 | F_FORWARD);
 * cache_end_insert(); // Commits both entries atomically
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DNS caching per RFC 1035
 * 
 * SIDE EFFECTS:
 * - Modifies cache hash table and LRU list for each committed entry
 * - Writes marshalled data to daemon->pipe_to_parent if child process
 * - Clears global new_chain and insert_error state
 * - Updates cache insertion metrics
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
/* after end of insertion, commit the new entries */
void cache_end_insert(void)
{
  if (insert_error)
    return;
  
  while (new_chain)
    { 
      struct crec *tmp = new_chain->next;
      /* drop CNAMEs which didn't find a target. */
      if (is_outdated_cname_pointer(new_chain))
	cache_free(new_chain);
      else
	{
	  cache_hash(new_chain);
	  cache_link(new_chain);
	  daemon->metrics[METRIC_DNS_CACHE_INSERTED]++;

	  /* If we're a child process, send this cache entry up the pipe to the master.
	     The marshalling process is rather nasty. */
	  if (daemon->pipe_to_parent != -1)
	    {
	      char *name = cache_get_name(new_chain);
	      ssize_t m = strlen(name);
	      unsigned int flags = new_chain->flags;
#ifdef HAVE_DNSSEC
	      u16 class = new_chain->uid;
#endif
	      
	      read_write(daemon->pipe_to_parent, (unsigned char *)&m, sizeof(m), 0);
	      read_write(daemon->pipe_to_parent, (unsigned char *)name, m, 0);
	      read_write(daemon->pipe_to_parent, (unsigned char *)&new_chain->ttd, sizeof(new_chain->ttd), 0);
	      read_write(daemon->pipe_to_parent, (unsigned  char *)&flags, sizeof(flags), 0);

	      if (flags & (F_IPV4 | F_IPV6 | F_DNSKEY | F_DS | F_SRV))
		read_write(daemon->pipe_to_parent, (unsigned char *)&new_chain->addr, sizeof(new_chain->addr), 0);
	      if (flags & F_SRV)
		{
		  /* A negative SRV entry is possible and has no data, obviously. */
		  if (!(flags & F_NEG))
		    blockdata_write(new_chain->addr.srv.target, new_chain->addr.srv.targetlen, daemon->pipe_to_parent);
		}
#ifdef HAVE_DNSSEC
	      if (flags & F_DNSKEY)
		{
		  read_write(daemon->pipe_to_parent, (unsigned char *)&class, sizeof(class), 0);
		  blockdata_write(new_chain->addr.key.keydata, new_chain->addr.key.keylen, daemon->pipe_to_parent);
		}
	      else if (flags & F_DS)
		{
		  read_write(daemon->pipe_to_parent, (unsigned char *)&class, sizeof(class), 0);
		  /* A negative DS entry is possible and has no data, obviously. */
		  if (!(flags & F_NEG))
		    blockdata_write(new_chain->addr.ds.keydata, new_chain->addr.ds.keylen, daemon->pipe_to_parent);
		}
#endif
	    }
	}
      
      new_chain = tmp;
    }

  /* signal end of cache insert in master process */
  if (daemon->pipe_to_parent != -1)
    {
      ssize_t m = -1;
      read_write(daemon->pipe_to_parent, (unsigned char *)&m, sizeof(m), 0);
    }
      
  new_chain = NULL;
}


/**
 * @brief Receive and unmarshall cache entries from child process
 * 
 * @detailed Reads marshalled cache entries sent by cache_end_insert() in child process
 * via file descriptor (pipe). Unmarshalls each entry including name, TTL, flags, and
 * type-specific data (IPv4/IPv6 addresses, SRV targets, DNSKEY/DS records), then inserts
 * into master process cache using really_insert(). Handles CNAME chaining by linking
 * newc->addr.cname.target.cache to previously received entry (crecp). Terminates when
 * receiving sentinel value m == -1. Returns 1 on successful completion, 0 on read error.
 * 
 * @param now Current time for TTL calculation
 * @param fd File descriptor (pipe from child) to read marshalled data from
 * 
 * @return 1 on successful receipt and insertion of all entries, 0 on read error
 * 
 * @note Only used in master process when daemon->pipe_to_parent != -1 in child
 * @note Calls cache_start_insert() internally to begin transaction
 * @note Calls cache_end_insert() when sentinel -1 received
 * @note Uses daemon->namebuff as buffer for reading DNS names
 * 
 * @warning Returns 0 immediately on any read error, leaving transaction uncommitted
 * @warning Not thread-safe (single-process event-driven architecture)
 * 
 * @see cache_end_insert() for marshalling format in child process
 * @see really_insert() for actual cache insertion
 * @see blockdata_read() for reading variable-length blockdata (SRV, DNSKEY, DS)
 * 
 * EXAMPLE USAGE:
 * @code
 * // In master process event loop when pipe from child readable
 * if (cache_recv_insert(time(NULL), daemon->child_pipe_fd) == 0)
 *   my_syslog(LOG_ERR, "Failed to receive cache entries from child");
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DNS caching per RFC 1035
 * 
 * SIDE EFFECTS:
 * - Reads data from file descriptor fd
 * - Inserts entries into cache hash table and LRU list
 * - Modifies daemon->namebuff
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
/* A marshalled cache entry arrives on fd, read, unmarshall and insert into cache of master process. */
int cache_recv_insert(time_t now, int fd)
{
  ssize_t m;
  union all_addr addr;
  unsigned long ttl;
  time_t ttd;
  unsigned int flags;
  struct crec *crecp = NULL;
  
  cache_start_insert();
  
  while(1)
    {
 
      if (!read_write(fd, (unsigned char *)&m, sizeof(m), 1))
	return 0;
      
      if (m == -1)
	{
	  cache_end_insert();
	  return 1;
	}

      if (!read_write(fd, (unsigned char *)daemon->namebuff, m, 1) ||
	  !read_write(fd, (unsigned char *)&ttd, sizeof(ttd), 1) ||
	  !read_write(fd, (unsigned char *)&flags, sizeof(flags), 1))
	return 0;

      daemon->namebuff[m] = 0;

      ttl = difftime(ttd, now);
      
      if (flags & (F_IPV4 | F_IPV6 | F_DNSKEY | F_DS | F_SRV))
	{
	  unsigned short class = C_IN;

	  if (!read_write(fd, (unsigned char *)&addr, sizeof(addr), 1))
	    return 0;

	  if ((flags & F_SRV) && !(flags & F_NEG) && !(addr.srv.target = blockdata_read(fd, addr.srv.targetlen)))
	    return 0;
	
#ifdef HAVE_DNSSEC
	   if (flags & F_DNSKEY)
	     {
	       if (!read_write(fd, (unsigned char *)&class, sizeof(class), 1) ||
		   !(addr.key.keydata = blockdata_read(fd, addr.key.keylen)))
		 return 0;
	     }
	   else  if (flags & F_DS)
	     {
	        if (!read_write(fd, (unsigned char *)&class, sizeof(class), 1) ||
		    (!(flags & F_NEG) && !(addr.key.keydata = blockdata_read(fd, addr.key.keylen))))
		  return 0;
	     }
#endif
	       
	  crecp = really_insert(daemon->namebuff, &addr, class, now, ttl, flags);
	}
      else if (flags & F_CNAME)
	{
	  struct crec *newc = really_insert(daemon->namebuff, NULL, C_IN, now, ttl, flags);
	  /* This relies on the fact that the target of a CNAME immediately precedes
	     it because of the order of extraction in extract_addresses, and
	     the order reversal on the new_chain. */
	  if (newc)
	    {
	       newc->addr.cname.is_name_ptr = 0;
	       
	       if (!crecp)
		 newc->addr.cname.target.cache = NULL;
	       else
		{
		  next_uid(crecp);
		  newc->addr.cname.target.cache = crecp;
		  newc->addr.cname.uid = crecp->uid;
		}
	    }
	}
    }
}
	
/**
 * @brief Check if name exists in cache as non-terminal (not NXDOMAIN)
 * 
 * @detailed Searches cache hash bucket for forward lookup entries matching name that are
 * not expired, not outdated CNAME pointers, and not NXDOMAIN (negative entries). Used to
 * determine if a domain name exists in DNS hierarchy even if specific query type not cached.
 * Returns 1 if any valid forward record found for name, 0 otherwise.
 * 
 * @param name DNS name to search for (null-terminated string)
 * @param now Current time for expiry checking
 * 
 * @return 1 if name exists in cache with valid forward entry, 0 if not found or only NXDOMAIN
 * 
 * @note Only searches F_FORWARD entries (not reverse lookups)
 * @note Excludes F_NXDOMAIN entries (negative cache)
 * @note Used for DNSSEC validation and authoritative DNS serving
 * 
 * @see cache_find_by_name() for retrieving actual cache records
 * @see is_expired() for TTL expiry checking
 * @see is_outdated_cname_pointer() for CNAME validity checking
 * 
 * EXAMPLE USAGE:
 * @code
 * if (cache_find_non_terminal("example.com", time(NULL)))
 *   // Name exists in cache (has at least one valid record)
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DNS name existence checking per RFC 1035
 * 
 * SIDE EFFECTS: None (read-only cache lookup)
 * 
 * THREAD SAFETY: Thread-safe for reads (single-process event-driven architecture)
 */
int cache_find_non_terminal(char *name, time_t now)
{
  struct crec *crecp;

  for (crecp = *hash_bucket(name); crecp; crecp = crecp->hash_next)
    if (!is_outdated_cname_pointer(crecp) &&
	!is_expired(now, crecp) &&
	(crecp->flags & F_FORWARD) &&
	!(crecp->flags & F_NXDOMAIN) && 
	hostname_isequal(name, cache_get_name(crecp)))
      return 1;

  return 0;
}

/**
 * @brief Search cache for entries matching domain name and protocol flags
 * 
 * @detailed Performs forward DNS cache lookup by name, returning matching cache records
 * that satisfy protocol flags (F_IPV4, F_IPV6, F_CNAME, etc.). On first call (crecp == NULL),
 * searches hash bucket, moves matching entries to front of LRU list (except F_HOSTS/F_DHCP/F_CONFIG),
 * frees expired entries, and implements round-robin by reordering hash chain. On subsequent calls
 * (crecp != NULL), iterates through linked list returned by first call. Returns first matching
 * non-expired entry or NULL if not found. F_NO_RR flag in prot suppresses round-robin reordering.
 * 
 * @param crecp Previous cache record for iteration (NULL for first call)
 * @param name DNS name to search for (null-terminated string)
 * @param now Current time for expiry checking
 * @param prot Protocol flags (F_IPV4, F_IPV6, F_CNAME, etc.) and F_NO_RR to disable round-robin
 * 
 * @return Pointer to matching cache record, or NULL if not found
 * 
 * @note First call (crecp == NULL) performs cache maintenance (expiry, LRU promotion)
 * @note Subsequent calls (crecp != NULL) iterate through ans chain built by first call
 * @note F_NO_RR flag disables round-robin reordering for authoritative responses
 * @note F_HOSTS, F_DHCP, F_CONFIG entries not moved in LRU (permanent entries)
 * @note Round-robin only groups entries with matching F_REVERSE and F_IMMORTAL flags
 * 
 * @warning Modifies hash chain order (round-robin) unless F_NO_RR specified
 * @warning Not thread-safe (modifies cache structure)
 * 
 * @see cache_find_by_addr() for reverse lookup by IP address
 * @see cache_find_non_terminal() for checking name existence
 * @see is_expired() for TTL expiry checking
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *crecp = NULL;
 * while ((crecp = cache_find_by_name(crecp, "www.example.com", time(NULL), F_IPV4)))
 *   // Process each IPv4 address for www.example.com
 * @endcode
 * 
 * RFC COMPLIANCE: Supports DNS caching and round-robin per RFC 1035
 * 
 * SIDE EFFECTS:
 * - Frees expired cache entries
 * - Moves entries in LRU list (except permanent entries)
 * - Reorders hash chain for round-robin (unless F_NO_RR)
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
struct crec *cache_find_by_name(struct crec *crecp, char *name, time_t now, unsigned int prot)
{
  struct crec *ans;
  int no_rr = prot & F_NO_RR;

  prot &= ~F_NO_RR;
  
  if (crecp) /* iterating */
    ans = crecp->next;
  else
    {
      /* first search, look for relevant entries and push to top of list
	 also free anything which has expired */
      struct crec *next, **up, **insert = NULL, **chainp = &ans;
      unsigned int ins_flags = 0;
      
      for (up = hash_bucket(name), crecp = *up; crecp; crecp = next)
	{
	  next = crecp->hash_next;
	  
	  if (!is_expired(now, crecp) && !is_outdated_cname_pointer(crecp))
	    {
	      if ((crecp->flags & F_FORWARD) && 
		  (crecp->flags & prot) &&
		  hostname_isequal(cache_get_name(crecp), name))
		{
		  if (crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG))
		    {
		      *chainp = crecp;
		      chainp = &crecp->next;
		    }
		  else
		    {
		      cache_unlink(crecp);
		      cache_link(crecp);
		    }
	      	      
		  /* Move all but the first entry up the hash chain
		     this implements round-robin. 
		     Make sure that re-ordering doesn't break the hash-chain
		     order invariants. 
		  */
		  if (insert && (crecp->flags & (F_REVERSE | F_IMMORTAL)) == ins_flags)
		    {
		      *up = crecp->hash_next;
		      crecp->hash_next = *insert;
		      *insert = crecp;
		      insert = &crecp->hash_next;
		    }
		  else
		    {
		      if (!insert && !no_rr)
			{
			  insert = up;
			  ins_flags = crecp->flags & (F_REVERSE | F_IMMORTAL);
			}
		      up = &crecp->hash_next; 
		    }
		}
	      else
		/* case : not expired, incorrect entry. */
		up = &crecp->hash_next; 
	    }
	  else
	    {
	      /* expired entry, free it */
	      *up = crecp->hash_next;
	      if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		{ 
		  cache_unlink(crecp);
		  cache_free(crecp);
		}
	    }
	}
	  
      *chainp = cache_head;
    }

  if (ans && 
      (ans->flags & F_FORWARD) &&
      (ans->flags & prot) &&     
      hostname_isequal(cache_get_name(ans), name))
    return ans;
  
  return NULL;
}

/**
 * @brief Search cache for reverse DNS entries matching IP address
 * 
 * @detailed Performs reverse DNS cache lookup by IP address, returning matching cache records
 * with F_REVERSE flag that satisfy protocol flags (F_IPV4 or F_IPV6). On first call (crecp == NULL),
 * iterates through ALL hash buckets (entire hash_table[]) searching for F_REVERSE entries,
 * moves matching entries to front of LRU list (except F_HOSTS/F_DHCP/F_CONFIG), and frees expired
 * entries. Terminates bucket search at first non-F_REVERSE entry (optimization: reverse entries
 * at start of chain). On subsequent calls (crecp != NULL), iterates through linked list built by
 * first call. Returns first matching non-expired entry or NULL if not found.
 * 
 * @param crecp Previous cache record for iteration (NULL for first call)
 * @param addr IP address to search for (IPv4 or IPv6 in union all_addr)
 * @param now Current time for expiry checking
 * @param prot Protocol flags (F_IPV4 or F_IPV6) determining address length
 * 
 * @return Pointer to matching reverse cache record, or NULL if not found
 * 
 * @note First call searches entire cache (all buckets), not single hash bucket
 * @note Only returns entries with F_REVERSE flag (PTR records)
 * @note Address length determined by prot: IN6ADDRSZ (16 bytes) for F_IPV6, INADDRSZ (4 bytes) for F_IPV4
 * @note F_HOSTS, F_DHCP, F_CONFIG entries not moved in LRU (permanent entries)
 * @note Search terminates at first non-F_REVERSE entry per bucket (efficiency)
 * 
 * @warning First call O(n) complexity (scans entire cache)
 * @warning Not thread-safe (modifies cache structure)
 * 
 * @see cache_find_by_name() for forward lookup by domain name
 * @see cache_make_stat() for reverse lookup statistics
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * inet_pton(AF_INET, "192.0.2.1", &addr.addr4);
 * struct crec *crecp = cache_find_by_addr(NULL, &addr, time(NULL), F_IPV4);
 * if (crecp)
 *   // Found PTR record for 192.0.2.1
 * @endcode
 * 
 * RFC COMPLIANCE: Supports reverse DNS (PTR) caching per RFC 1035
 * 
 * SIDE EFFECTS:
 * - Frees expired reverse cache entries
 * - Moves entries in LRU list (except permanent entries)
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
struct crec *cache_find_by_addr(struct crec *crecp, union all_addr *addr, 
				time_t now, unsigned int prot)
{
  struct crec *ans;
  int addrlen = (prot == F_IPV6) ? IN6ADDRSZ : INADDRSZ;
  
  if (crecp) /* iterating */
    ans = crecp->next;
  else
    {  
      /* first search, look for relevant entries and push to top of list
	 also free anything which has expired. All the reverse entries are at the
	 start of the hash chain, so we can give up when we find the first 
	 non-REVERSE one.  */
       int i;
       struct crec **up, **chainp = &ans;
       
       for (i=0; i<hash_size; i++)
	 for (crecp = hash_table[i], up = &hash_table[i]; 
	      crecp && (crecp->flags & F_REVERSE);
	      crecp = crecp->hash_next)
	   if (!is_expired(now, crecp))
	     {      
	       if ((crecp->flags & prot) &&
		   memcmp(&crecp->addr, addr, addrlen) == 0)
		 {	    
		   if (crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG))
		     {
		       *chainp = crecp;
		       chainp = &crecp->next;
		     }
		   else
		     {
		       cache_unlink(crecp);
		       cache_link(crecp);
		     }
		 }
	       up = &crecp->hash_next;
	     }
	   else
	     {
	       *up = crecp->hash_next;
	       if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		 {
		   cache_unlink(crecp);
		   cache_free(crecp);
		 }
	     }
       
       *chainp = cache_head;
    }
  
  if (ans && 
      (ans->flags & F_REVERSE) &&
      (ans->flags & prot) &&
      memcmp(&ans->addr, addr, addrlen) == 0)
    return ans;
  
  return NULL;
}

/**
 * @brief Add hosts file entry to cache with deduplication
 * 
 * @detailed Inserts hosts file entry (from /etc/hosts or --addn-hosts) into cache with forward
 * (name→address) and reverse (address→name) mappings. Deduplicates: frees cache if identical entry
 * already exists (same name+address+F_HOSTS). Prevents multiple reverse PTR for same address:
 * first occurrence wins, later entries get F_REVERSE cleared. For bulk reads (rhash non-NULL),
 * uses temporary hash table rhash[hashsz] hashed on address to achieve O(n) deduplication instead
 * of O(n²) cache lookups. For incremental reads (rhash==NULL), uses cache_find_by_addr() for
 * deduplication. Sets cache->uid = index (source file identifier). Copies address, hashes entry
 * via cache_hash(), creates parent non-terminals via make_non_terminals().
 * 
 * @param cache Pre-allocated crec with name and flags set, address and uid unset
 * @param addr IP address for this hosts entry (union all_addr)
 * @param addrlen Address length (INADDRSZ for IPv4, IN6ADDRSZ for IPv6)
 * @param index Source file UID (SRC_HOSTS, or unique ID from daemon->addn_hosts)
 * @param rhash Temporary address hash table for bulk deduplication, NULL for incremental reads
 * @param hashsz Size of rhash array if non-NULL, ignored if rhash==NULL
 * 
 * @return void
 * 
 * @note Frees cache and returns immediately if duplicate name+address+F_HOSTS found
 * @note Clears F_REVERSE flag if address already has reverse PTR (first wins)
 * @note rhash temporary hash uses cache->next pointer, freed after hosts read complete
 * @note rhash optimization prevents O(n²) behavior for large (10000+ entry) hosts files
 * @note Incremental reads (rhash==NULL) use cache_find_by_addr() for deduplication
 * @note Always calls cache_hash() and make_non_terminals() for successful inserts
 * 
 * @warning cache freed if duplicate, caller must not use after call
 * @warning rhash and cache->next only valid during hosts file reading
 * 
 * @see read_hostsfile() caller for bulk hosts file loading
 * @see cache_hash() for inserting into main cache hash table
 * @see make_non_terminals() for creating parent domain entries
 * @see cache_find_by_name() for duplicate detection
 * @see cache_find_by_addr() for reverse PTR deduplication
 * 
 * EXAMPLE USAGE:
 * @code
 * // Internal use by read_hostsfile()
 * struct crec *cache = whine_malloc(SIZEOF_BARE_CREC + strlen(name) + 1);
 * strcpy(cache->name.sname, name);
 * cache->flags = F_HOSTS | F_IPV4 | F_FORWARD | F_REVERSE;
 * cache->ttd = daemon->local_ttl;
 * add_hosts_entry(cache, &addr, INADDRSZ, SRC_HOSTS, rhash, hashsz);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific hosts file processing)
 * 
 * SIDE EFFECTS:
 * - Frees cache if duplicate entry found
 * - Sets cache->uid = index
 * - Copies addr to cache->addr
 * - Inserts cache into main hash table via cache_hash()
 * - Creates parent non-terminals via make_non_terminals()
 * - May clear F_REVERSE if address already has PTR
 * - For bulk reads: adds to rhash temporary hash chain
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
static void add_hosts_entry(struct crec *cache, union all_addr *addr, int addrlen, 
			    unsigned int index, struct crec **rhash, int hashsz)
{
  struct crec *lookup = cache_find_by_name(NULL, cache_get_name(cache), 0, cache->flags & (F_IPV4 | F_IPV6));
  int i;
  unsigned int j; 

  /* Remove duplicates in hosts files. */
  if (lookup && (lookup->flags & F_HOSTS) && memcmp(&lookup->addr, addr, addrlen) == 0)
    {
      free(cache);
      return;
    }
    
  /* Ensure there is only one address -> name mapping (first one trumps) 
     We do this by steam here, The entries are kept in hash chains, linked
     by ->next (which is unused at this point) held in hash buckets in
     the array rhash, hashed on address. Note that rhash and the values
     in ->next are only valid  whilst reading hosts files: the buckets are
     then freed, and the ->next pointer used for other things. 

     Only insert each unique address once into this hashing structure.

     This complexity avoids O(n^2) divergent CPU use whilst reading
     large (10000 entry) hosts files. 

     Note that we only do this process when bulk-reading hosts files, 
     for incremental reads, rhash is NULL, and we use cache lookups
     instead.
  */
  
  if (rhash)
    {
      /* hash address */
      for (j = 0, i = 0; i < addrlen; i++)
	j = (j*2 +((unsigned char *)addr)[i]) % hashsz;
      
      for (lookup = rhash[j]; lookup; lookup = lookup->next)
	if ((lookup->flags & cache->flags & (F_IPV4 | F_IPV6)) &&
	    memcmp(&lookup->addr, addr, addrlen) == 0)
	  {
	    cache->flags &= ~F_REVERSE;
	    break;
	  }
      
      /* maintain address hash chain, insert new unique address */
      if (!lookup)
	{
	  cache->next = rhash[j];
	  rhash[j] = cache;
	}
    }
  else
    {
      /* incremental read, lookup in cache */
      lookup = cache_find_by_addr(NULL, addr, 0, cache->flags & (F_IPV4 | F_IPV6));
      if (lookup && lookup->flags & F_HOSTS)
	cache->flags &= ~F_REVERSE;
    }

  cache->uid = index;
  memcpy(&cache->addr, addr, addrlen);  
  cache_hash(cache);
  make_non_terminals(cache);
}

static int eatspace(FILE *f)
{
  int c, nl = 0;

  while (1)
    {
      if ((c = getc(f)) == '#')
	while (c != '\n' && c != EOF)
	  c = getc(f);
      
      if (c == EOF)
	return 1;

      if (!isspace(c))
	{
	  ungetc(c, f);
	  return nl;
	}

      if (c == '\n')
	nl++;
    }
}
	 
static int gettok(FILE *f, char *token)
{
  int c, count = 0;
 
  while (1)
    {
      if ((c = getc(f)) == EOF)
	return (count == 0) ? -1 : 1;

      if (isspace(c) || c == '#')
	{
	  ungetc(c, f);
	  return eatspace(f);
	}
      
      if (count < (MAXDNAME - 1))
	{
	  token[count++] = c;
	  token[count] = 0;
	}
    }
}

/**
 * @brief Parse hosts file and populate cache with static hostname→IP mappings
 * 
 * @detailed Reads /etc/hosts-format file line-by-line, parsing IPv4/IPv6 addresses followed
 * by space-separated hostnames. Creates cache entries with F_HOSTS | F_IMMORTAL | F_FORWARD |
 * F_REVERSE flags. If OPT_EXPAND enabled, creates additional entries with domain_suffix appended
 * to non-FQDN names. Performs incremental rehashing every 1000 names for efficiency. All entries
 * get TTL = daemon->local_ttl. Returns count of names loaded (may exceed cache_size). Logs
 * errors for malformed addresses/names. Calls add_hosts_entry() to merge with existing cache.
 * 
 * @param filename Path to hosts file (e.g., "/etc/hosts")
 * @param index Record source identifier for record_source() tracking
 * @param cache_size Current cache size before loading (name count)
 * @param rhash Reverse lookup hash table for duplicate detection, or NULL during initialization
 * @param hashsz Size of rhash table
 * 
 * @return Total name count after loading (cache_size + newly loaded names)
 * 
 * @note Entries marked F_IMMORTAL never expire (TTL used only for local_ttl display)
 * @note Canonicalizes names using canonicalise() before insertion
 * @note Rehashes cache every 1000 new names if rhash non-NULL
 * @note Performs final rehash after all names loaded
 * @note Logs total address count to syslog at LOG_INFO
 * 
 * @warning Returns cache_size unchanged if file open fails (errno logged)
 * @warning Malformed addresses skip entire line, malformed names skip that name only
 * @warning Memory allocation failures skip entry (whine_malloc() logs error)
 * 
 * @see add_hosts_entry() for duplicate detection and cache insertion
 * @see canonicalise() for name validation and canonicalization
 * @see cache_reload() which calls this for all configured hosts files
 * 
 * EXAMPLE USAGE:
 * @code
 * int count = read_hostsfile("/etc/hosts", 0, 0, hash_table, HASH_SIZE);
 * my_syslog(LOG_INFO, "Loaded %d hostnames from /etc/hosts", count);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * RFC 952: Hostname syntax. RFC 1123: Hostname syntax relaxation.
 * 
 * SIDE EFFECTS:
 * - Opens and reads file descriptor
 * - Allocates cache entries (malloc)
 * - Modifies cache hash table and LRU list
 * - May trigger cache rehashing
 * - Logs to syslog
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
int read_hostsfile(char *filename, unsigned int index, int cache_size, struct crec **rhash, int hashsz)
{  
  FILE *f = fopen(filename, "r");
  char *token = daemon->namebuff, *domain_suffix = NULL;
  int addr_count = 0, name_count = cache_size, lineno = 1;
  unsigned int flags = 0;
  union all_addr addr;
  int atnl, addrlen = 0;

  if (!f)
    {
      my_syslog(LOG_ERR, _("failed to load names from %s: %s"), filename, strerror(errno));
      return cache_size;
    }
  
  lineno += eatspace(f);
  
  while ((atnl = gettok(f, token)) != -1)
    {
      if (inet_pton(AF_INET, token, &addr) > 0)
	{
	  flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV4;
	  addrlen = INADDRSZ;
	  domain_suffix = get_domain(addr.addr4);
	}
      else if (inet_pton(AF_INET6, token, &addr) > 0)
	{
	  flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV6;
	  addrlen = IN6ADDRSZ;
	  domain_suffix = get_domain6(&addr.addr6);
	}
      else
	{
	  my_syslog(LOG_ERR, _("bad address at %s line %d"), filename, lineno); 
	  while (atnl == 0)
	    atnl = gettok(f, token);
	  lineno += atnl;
	  continue;
	}
      
      addr_count++;
      
      /* rehash every 1000 names. */
      if (rhash && ((name_count - cache_size) > 1000))
	{
	  rehash(name_count);
	  cache_size = name_count;
	} 
      
      while (atnl == 0)
	{
	  struct crec *cache;
	  int fqdn, nomem;
	  char *canon;
	  
	  if ((atnl = gettok(f, token)) == -1)
	    break;

	  fqdn = !!strchr(token, '.');

	  if ((canon = canonicalise(token, &nomem)))
	    {
	      /* If set, add a version of the name with a default domain appended */
	      if (option_bool(OPT_EXPAND) && domain_suffix && !fqdn && 
		  (cache = whine_malloc(SIZEOF_BARE_CREC + strlen(canon) + 2 + strlen(domain_suffix))))
		{
		  strcpy(cache->name.sname, canon);
		  strcat(cache->name.sname, ".");
		  strcat(cache->name.sname, domain_suffix);
		  cache->flags = flags;
		  cache->ttd = daemon->local_ttl;
		  add_hosts_entry(cache, &addr, addrlen, index, rhash, hashsz);
		  name_count++;
		}
	      if ((cache = whine_malloc(SIZEOF_BARE_CREC + strlen(canon) + 1)))
		{
		  strcpy(cache->name.sname, canon);
		  cache->flags = flags;
		  cache->ttd = daemon->local_ttl;
		  add_hosts_entry(cache, &addr, addrlen, index, rhash, hashsz);
		  name_count++;
		}
	      free(canon);
	      
	    }
	  else if (!nomem)
	    my_syslog(LOG_ERR, _("bad name at %s line %d"), filename, lineno); 
	}

      lineno += atnl;
    } 

  fclose(f);
  
  if (rhash)
    rehash(name_count); 
  
  my_syslog(LOG_INFO, _("read %s - %d addresses"), filename, addr_count);
  
  return name_count;
}
	    
/**
 * @brief Reload cache with static configuration from config files and hosts files
 * 
 * @detailed Called on daemon startup and SIGHUP to repopulate cache with static configuration:
 * (1) Removes all F_HOSTS and F_CONFIG entries from cache, preserves F_DHCP entries and dynamic
 * DNS cache. (2) Frees blockdata and bigname structures for removed entries. (3) Re-adds CNAMEs
 * from daemon->cnames. (4) Re-adds DS records from daemon->ds (DNSSEC). (5) Re-adds host_records
 * from daemon->host_records (IPv4/IPv6 A/AAAA). (6) Re-adds MX/SRV/TXT records from config.
 * (7) Calls read_hostsfile() for each configured hosts file. Uses temporary reverse hash in
 * daemon->packet buffer for duplicate detection during load. Resets cache metrics.
 * 
 * @return void
 * 
 * @note Preserves F_DHCP entries (DHCP leases not cleared)
 * @note Preserves dynamic DNS cache entries (non-F_HOSTS, non-F_CONFIG, non-F_DHCP)
 * @note All F_HOSTS and F_CONFIG entries get F_IMMORTAL flag (never expire)
 * @note Uses daemon->packet buffer as temporary reverse hash (revhashsz = packet_buff_sz / sizeof(struct crec *))
 * @note Overwrites daemon->srv_save = NULL (borrows packet buffer)
 * @note Resets daemon->metrics[METRIC_DNS_CACHE_INSERTED] and [METRIC_DNS_CACHE_LIVE_FREED] to 0
 * 
 * @warning Not thread-safe (modifies cache hash table)
 * @warning Overwrites daemon->packet buffer temporarily (restored after hosts file loading)
 * 
 * @see read_hostsfile() for hosts file parsing
 * @see cache_hash() for inserting configured entries
 * @see add_hosts_entry() for duplicate detection
 * @see make_non_terminals() for creating non-terminal domain entries
 * 
 * EXAMPLE USAGE:
 * @code
 * // On SIGHUP signal handler
 * read_opts(argc, argv, NULL); // Reload configuration
 * cache_reload(); // Repopulate cache with static config
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific cache management)
 * 
 * SIDE EFFECTS:
 * - Frees all F_HOSTS and F_CONFIG cache entries
 * - Frees blockdata for removed entries
 * - Re-allocates and re-hashes static configuration entries
 * - Reads all configured hosts files
 * - Resets cache insertion metrics
 * - Overwrites daemon->packet buffer temporarily
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
void cache_reload(void)
{
  struct crec *cache, **up, *tmp;
  int revhashsz, i, total_size = daemon->cachesize;
  struct hostsfile *ah;
  struct host_record *hr;
  struct name_list *nl;
  struct cname *a;
  struct crec lrec;
  struct mx_srv_record *mx;
  struct txt_record *txt;
  struct interface_name *intr;
  struct ptr_record *ptr;
  struct naptr *naptr;
#ifdef HAVE_DNSSEC
  struct ds_config *ds;
#endif

  daemon->metrics[METRIC_DNS_CACHE_INSERTED] = 0;
  daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED] = 0;
  
  for (i=0; i<hash_size; i++)
    for (cache = hash_table[i], up = &hash_table[i]; cache; cache = tmp)
      {
	cache_blockdata_free(cache);

	tmp = cache->hash_next;
	if (cache->flags & (F_HOSTS | F_CONFIG))
	  {
	    *up = cache->hash_next;
	    free(cache);
	  }
	else if (!(cache->flags & F_DHCP))
	  {
	    *up = cache->hash_next;
	    if (cache->flags & F_BIGNAME)
	      {
		cache->name.bname->next = big_free;
		big_free = cache->name.bname;
	      }
	    cache->flags = 0;
	  }
	else
	  up = &cache->hash_next;
      }
  
  /* Add locally-configured CNAMEs to the cache */
  for (a = daemon->cnames; a; a = a->next)
    if (a->alias[1] != '*' &&
	((cache = whine_malloc(SIZEOF_POINTER_CREC))))
      {
	cache->flags = F_FORWARD | F_NAMEP | F_CNAME | F_IMMORTAL | F_CONFIG;
	cache->ttd = a->ttl;
	cache->name.namep = a->alias;
	cache->addr.cname.target.name = a->target;
	cache->addr.cname.is_name_ptr = 1;
	cache->uid = UID_NONE;
	cache_hash(cache);
	make_non_terminals(cache);
      }
  
#ifdef HAVE_DNSSEC
  for (ds = daemon->ds; ds; ds = ds->next)
    if ((cache = whine_malloc(SIZEOF_POINTER_CREC)) &&
	(cache->addr.ds.keydata = blockdata_alloc(ds->digest, ds->digestlen)))
      {
	cache->flags = F_FORWARD | F_IMMORTAL | F_DS | F_CONFIG | F_NAMEP;
	cache->ttd = daemon->local_ttl;
	cache->name.namep = ds->name;
	cache->addr.ds.keylen = ds->digestlen;
	cache->addr.ds.algo = ds->algo;
	cache->addr.ds.keytag = ds->keytag;
	cache->addr.ds.digest = ds->digest_type;
	cache->uid = ds->class;
	cache_hash(cache);
	make_non_terminals(cache);
      }
#endif
  
  /* borrow the packet buffer for a temporary by-address hash */
  memset(daemon->packet, 0, daemon->packet_buff_sz);
  revhashsz = daemon->packet_buff_sz / sizeof(struct crec *);
  /* we overwrote the buffer... */
  daemon->srv_save = NULL;

  /* Do host_records in config. */
  for (hr = daemon->host_records; hr; hr = hr->next)
    for (nl = hr->names; nl; nl = nl->next)
      {
	if ((hr->flags & HR_4) &&
	    (cache = whine_malloc(SIZEOF_POINTER_CREC)))
	  {
	    cache->name.namep = nl->name;
	    cache->ttd = hr->ttl;
	    cache->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV4 | F_NAMEP | F_CONFIG;
	    add_hosts_entry(cache, (union all_addr *)&hr->addr, INADDRSZ, SRC_CONFIG, (struct crec **)daemon->packet, revhashsz);
	  }

	if ((hr->flags & HR_6) &&
	    (cache = whine_malloc(SIZEOF_POINTER_CREC)))
	  {
	    cache->name.namep = nl->name;
	    cache->ttd = hr->ttl;
	    cache->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV6 | F_NAMEP | F_CONFIG;
	    add_hosts_entry(cache, (union all_addr *)&hr->addr6, IN6ADDRSZ, SRC_CONFIG, (struct crec **)daemon->packet, revhashsz);
	  }
      }
	
  if (option_bool(OPT_NO_HOSTS) && !daemon->addn_hosts)
    {
      if (daemon->cachesize > 0)
	my_syslog(LOG_INFO, _("cleared cache"));
    }
  else
    {
      if (!option_bool(OPT_NO_HOSTS))
	total_size = read_hostsfile(HOSTSFILE, SRC_HOSTS, total_size, (struct crec **)daemon->packet, revhashsz);
      
      daemon->addn_hosts = expand_filelist(daemon->addn_hosts);
      for (ah = daemon->addn_hosts; ah; ah = ah->next)
	if (!(ah->flags & AH_INACTIVE))
	  total_size = read_hostsfile(ah->fname, ah->index, total_size, (struct crec **)daemon->packet, revhashsz);
    }
  
  /* Make non-terminal records for all locally-define RRs */
  lrec.flags = F_FORWARD | F_CONFIG | F_NAMEP | F_IMMORTAL;
  
  for (txt = daemon->txt; txt; txt = txt->next)
    {
      lrec.name.namep = txt->name;
      make_non_terminals(&lrec);
    }

  for (naptr = daemon->naptr; naptr; naptr = naptr->next)
    {
      lrec.name.namep = naptr->name;
      make_non_terminals(&lrec);
    }

  for (mx = daemon->mxnames; mx; mx = mx->next)
    {
      lrec.name.namep = mx->name;
      make_non_terminals(&lrec);
    }

  for (intr = daemon->int_names; intr; intr = intr->next)
    {
      lrec.name.namep = intr->name;
      make_non_terminals(&lrec);
    }
  
  for (ptr = daemon->ptr; ptr; ptr = ptr->next)
    {
      lrec.name.namep = ptr->name;
      make_non_terminals(&lrec);
    }
  
#ifdef HAVE_INOTIFY
  set_dynamic_inotify(AH_HOSTS, total_size, (struct crec **)daemon->packet, revhashsz);
#endif
  
} 

#ifdef HAVE_DHCP
/**
 * @brief Look up IPv4 address for hostname from /etc/hosts cache
 * 
 * @detailed Searches cache for IPv4 A records with F_HOSTS flag (from /etc/hosts file) matching
 * name. Returns first matching IPv4 address. Used by DHCP server to resolve hostnames configured
 * with IP addresses from hosts file. Returns 0.0.0.0 if no match found or DNS service disabled
 * (daemon->port == 0). Logs warning at MS_DHCP | LOG_WARNING if no address found.
 * 
 * @param name Hostname to look up (null-terminated string, e.g., "server.example.com")
 * @param now Current time for expiry checking
 * 
 * @return IPv4 address (struct in_addr) if found, 0.0.0.0 (ret.s_addr = 0) if not found
 * 
 * @note Only returns addresses from /etc/hosts (F_HOSTS flag), ignores DHCP and dynamic DNS
 * @note Returns immediately with 0.0.0.0 if DNS service disabled (daemon->port == 0)
 * @note Logs warning if no address found (syslog MS_DHCP | LOG_WARNING)
 * @note Iterates through all IPv4 records for name, returns first with F_HOSTS
 * 
 * @see cache_find_by_name() for cache lookup
 * @see read_hostsfile() for populating F_HOSTS entries
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in_addr addr = a_record_from_hosts("gateway", time(NULL));
 * if (addr.s_addr != 0)
 *   // Use addr for DHCP configuration
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific DHCP-to-hosts integration)
 * 
 * SIDE EFFECTS:
 * - Logs warning to syslog if name not found
 * - Read-only cache lookup otherwise
 * 
 * THREAD SAFETY: Thread-safe for reads (single-process event-driven architecture)
 */
struct in_addr a_record_from_hosts(char *name, time_t now)
{
  struct crec *crecp = NULL;
  struct in_addr ret;
  
  /* If no DNS service, cache not initialised. */
  if (daemon->port != 0)
    while ((crecp = cache_find_by_name(crecp, name, now, F_IPV4)))
      if (crecp->flags & F_HOSTS)
	return crecp->addr.addr4;
  
  my_syslog(MS_DHCP | LOG_WARNING, _("No IPv4 address found for %s"), name);
  
  ret.s_addr = 0;
  return ret;
}

/**
 * @brief Remove all DHCP entries from cache hash table and move to spare list
 * 
 * @detailed Iterates through entire cache hash table, removes all entries with F_DHCP flag
 * from hash chains, and links them into dhcp_spare freelist. Does NOT free memory, preserves
 * entries for reuse. Called before re-adding DHCP hostname entries during lease reload or
 * daemon restart. Prepares cache for fresh DHCP hostname insertion without duplicates.
 * 
 * @return void
 * 
 * @note Does NOT free cache entries, moves to dhcp_spare list for reuse
 * @note Only removes from hash table, does NOT remove from LRU list
 * @note F_DHCP entries remain allocated, ready for cache_add_dhcp_entry() reuse
 * @note Called before bulk DHCP lease hostname re-insertion
 * 
 * @warning Leaves cache in inconsistent state (LRU list may still reference removed entries)
 * @warning Must call cache_add_dhcp_entry() or similar to restore consistency
 * 
 * @see cache_add_dhcp_entry() for re-inserting DHCP entries
 * @see dhcp_spare for spare entry freelist
 * 
 * EXAMPLE USAGE:
 * @code
 * cache_unhash_dhcp(); // Remove all DHCP entries
 * // Re-add current DHCP leases
 * for (each active lease)
 *   cache_add_dhcp_entry(hostname, F_IPV4, &addr, expiry);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific cache management)
 * 
 * SIDE EFFECTS:
 * - Removes all F_DHCP entries from hash_table[] chains
 * - Links removed entries to dhcp_spare freelist
 * - Modifies cache structure
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
void cache_unhash_dhcp(void)
{
  struct crec *cache, **up;
  int i;

  for (i=0; i<hash_size; i++)
    for (cache = hash_table[i], up = &hash_table[i]; cache; cache = cache->hash_next)
      if (cache->flags & F_DHCP)
	{
	  *up = cache->hash_next;
	  cache->next = dhcp_spare;
	  dhcp_spare = cache;
	}
      else
	up = &cache->hash_next;
}

/**
 * @brief Add DHCP hostname to cache with IP address binding
 * 
 * @detailed Adds DHCP lease hostname to DNS cache with forward (A/AAAA) and optionally reverse
 * (PTR) entries. Checks for conflicts with /etc/hosts (F_HOSTS) and static config (F_CONFIG).
 * If name already exists in hosts with different address, logs warning and skips insertion
 * to prevent /etc/hosts override. If name exists in hosts with same address, skips DHCP entry
 * (hosts entry sufficient). Removes conflicting non-DHCP dynamic entries before insertion.
 * Allocates new crec from dhcp_spare list (reuse after cache_unhash_dhcp()) or malloc().
 * Creates F_DHCP | F_FORWARD | F_NAMEP entry, optionally adds F_REVERSE if no PTR exists.
 * Sets F_IMMORTAL if ttd==0 (infinite lease), otherwise uses ttd as expiry.
 * 
 * @param host_name DHCP client hostname (null-terminated, not copied - must remain valid)
 * @param prot Address family (AF_INET for IPv4, AF_INET6 for IPv6)
 * @param host_address IP address (union all_addr pointer, copied into crec)
 * @param ttd Time To Die - absolute expiry time (seconds since epoch), 0 for infinite lease
 * 
 * @return void
 * 
 * @note host_name pointer stored directly (F_NAMEP), must remain valid for lease lifetime
 * @note Skips insertion if name exists in /etc/hosts with same address (redundant)
 * @note Logs warning and skips if name in /etc/hosts with different address (conflict)
 * @note Logs warning and skips if name is CNAME in /etc/hosts (invalid for DHCP)
 * @note Removes conflicting dynamic (non-DHCP, non-HOSTS, non-CONFIG) entries
 * @note Creates reverse PTR entry (F_REVERSE) if no existing reverse mapping
 * @note Allocates from dhcp_spare list if available, otherwise malloc()
 * @note Calls make_non_terminals() to create parent domain non-terminal entries
 * @note Silent failure if malloc() fails (logs via whine_malloc)
 * 
 * @warning host_name must remain valid (not freed) for lifetime of cache entry
 * @warning Uses global daemon->addrbuff and daemon->namebuff for temporary formatting
 * 
 * @see cache_unhash_dhcp() for removing old DHCP entries before re-adding
 * @see dhcp_spare for reusable DHCP entry freelist
 * @see cache_find_by_name() for conflict checking
 * @see cache_find_by_addr() for reverse entry checking
 * @see record_source() for formatting conflict warning messages
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("192.168.1.100");
 * time_t expiry = time(NULL) + 3600; // 1 hour lease
 * cache_add_dhcp_entry("client-pc", AF_INET, &addr, expiry);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific DHCP-DNS integration)
 * 
 * SIDE EFFECTS:
 * - Adds forward A/AAAA entry to cache (F_DHCP | F_FORWARD)
 * - May add reverse PTR entry (F_DHCP | F_REVERSE) if none exists
 * - May remove conflicting dynamic entries via cache_scan_free()
 * - Logs warnings for conflicts with /etc/hosts
 * - Calls make_non_terminals() creating parent domain entries
 * - Allocates memory via whine_malloc() if dhcp_spare empty
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
void cache_add_dhcp_entry(char *host_name, int prot,
			  union all_addr *host_address, time_t ttd) 
{
  struct crec *crec = NULL, *fail_crec = NULL;
  unsigned int flags = F_IPV4;
  int in_hosts = 0;
  size_t addrlen = sizeof(struct in_addr);

  if (prot == AF_INET6)
    {
      flags = F_IPV6;
      addrlen = sizeof(struct in6_addr);
    }
  
  inet_ntop(prot, host_address, daemon->addrbuff, ADDRSTRLEN);
  
  while ((crec = cache_find_by_name(crec, host_name, 0, flags | F_CNAME)))
    {
      /* check all addresses associated with name */
      if (crec->flags & (F_HOSTS | F_CONFIG))
	{
	  if (crec->flags & F_CNAME)
	    my_syslog(MS_DHCP | LOG_WARNING, 
		      _("%s is a CNAME, not giving it to the DHCP lease of %s"),
		      host_name, daemon->addrbuff);
	  else if (memcmp(&crec->addr, host_address, addrlen) == 0)
	    in_hosts = 1;
	  else
	    fail_crec = crec;
	}
      else if (!(crec->flags & F_DHCP))
	{
	  cache_scan_free(host_name, NULL, C_IN, 0, crec->flags & (flags | F_CNAME | F_FORWARD), NULL, NULL);
	  /* scan_free deletes all addresses associated with name */
	  break;
	}
    }
  
  /* if in hosts, don't need DHCP record */
  if (in_hosts)
    return;
  
  /* Name in hosts, address doesn't match */
  if (fail_crec)
    {
      inet_ntop(prot, &fail_crec->addr, daemon->namebuff, MAXDNAME);
      my_syslog(MS_DHCP | LOG_WARNING, 
		_("not giving name %s to the DHCP lease of %s because "
		  "the name exists in %s with address %s"), 
		host_name, daemon->addrbuff,
		record_source(fail_crec->uid), daemon->namebuff);
      return;
    }	  
  
  if ((crec = cache_find_by_addr(NULL, (union all_addr *)host_address, 0, flags)))
    {
      if (crec->flags & F_NEG)
	{
	  flags |= F_REVERSE;
	  cache_scan_free(NULL, (union all_addr *)host_address, C_IN, 0, flags, NULL, NULL);
	}
    }
  else
    flags |= F_REVERSE;
  
  if ((crec = dhcp_spare))
    dhcp_spare = dhcp_spare->next;
  else /* need new one */
    crec = whine_malloc(SIZEOF_POINTER_CREC);
  
  if (crec) /* malloc may fail */
    {
      crec->flags = flags | F_NAMEP | F_DHCP | F_FORWARD;
      if (ttd == 0)
	crec->flags |= F_IMMORTAL;
      else
	crec->ttd = ttd;
      crec->addr = *host_address;
      crec->name.namep = host_name;
      crec->uid = UID_NONE;
      cache_hash(crec);
      make_non_terminals(crec);
    }
}
#endif

/**
 * @brief Create non-terminal domain entries for parent domains of a cache entry
 * 
 * @detailed Called after inserting local/DHCP/hosts name to create empty parent domain entries
 * preventing NXDOMAIN for intermediate domains. For "three.two.one.example.com", creates entries
 * for "two.one.example.com", "one.example.com", "example.com" without F_IPV4/F_IPV6/F_CNAME set.
 * Converts NXDOMAIN responses for parent domains to NODATA (empty answer), allowing delegation.
 * First deletes any empty non-terminal for exact name from previous runs (type-matched: DHCP→DHCP,
 * HOSTS/CONFIG→HOSTS/CONFIG). Then walks domain labels rightward creating missing non-terminals.
 * Reuses existing non-terminals, extending TTD if source expires later. Allocates from dhcp_spare
 * for F_DHCP source, malloc for HOSTS/CONFIG. Sets F_NAMEP with pointer to substring in source name.
 * 
 * @param source Cache record to create parent non-terminals for (F_DHCP, F_HOSTS, or F_CONFIG)
 * 
 * @return void
 * 
 * @note Called by cache_add_dhcp_entry(), add_hosts_entry(), and really_insert()
 * @note Non-terminals have F_FORWARD but NO F_IPV4/F_IPV6/F_CNAME/F_SRV/F_DNSKEY/F_DS
 * @note First deletes old empty non-terminal for source name (cleanup from previous insertion)
 * @note Only deletes/creates non-terminals matching source type (DHCP vs HOSTS/CONFIG)
 * @note Extends non-terminal TTD if source has later expiry (preserves longest TTL)
 * @note F_IMMORTAL propagates from source to non-terminals if source immortal
 * @note Uses F_NAMEP with pointer into source name string (no allocation for name)
 * @note DHCP non-terminals allocated from dhcp_spare, freed when DHCP reloaded
 * @note HOSTS/CONFIG non-terminals malloced, freed when hosts file re-read
 * 
 * @warning source name must remain valid (F_NAMEP points into it) for non-terminal lifetime
 * @warning Silent failure if malloc() fails for HOSTS/CONFIG non-terminal
 * 
 * @see cache_add_dhcp_entry() caller for DHCP names
 * @see add_hosts_entry() caller for hosts file names
 * @see F_NAMEP flag indicating name stored as pointer, not copied
 * 
 * EXAMPLE USAGE:
 * @code
 * // Internal call after inserting "host.example.com"
 * make_non_terminals(crecp); // Creates "example.com" if missing
 * // Now queries for "example.com" return NODATA instead of NXDOMAIN
 * @endcode
 * 
 * RFC COMPLIANCE: Implements DNS delegation semantics, prevents false NXDOMAIN
 * 
 * SIDE EFFECTS:
 * - Deletes old empty non-terminal for source name (if exists)
 * - Creates new non-terminal cache entries for each parent domain label
 * - Extends TTD of existing non-terminals if source TTD later
 * - Allocates from dhcp_spare or malloc for new non-terminals
 * - Hashes new non-terminals via cache_hash()
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
/* Called when we put a local or DHCP name into the cache.
   Creates empty cache entries for subnames (ie,
   for three.two.one, for two.one and one), without
   F_IPV4 or F_IPV6 or F_CNAME set. These convert
   NXDOMAIN answers to NoData ones. */
static void make_non_terminals(struct crec *source)
{
  char *name = cache_get_name(source);
  struct crec *crecp, *tmp, **up;
  int type = F_HOSTS | F_CONFIG;
#ifdef HAVE_DHCP
  if (source->flags & F_DHCP)
    type = F_DHCP;
#endif
  
  /* First delete any empty entries for our new real name. Note that
     we only delete empty entries deriving from DHCP for a new DHCP-derived
     entry and vice-versa for HOSTS and CONFIG. This ensures that 
     non-terminals from DHCP go when we reload DHCP and 
     for HOSTS/CONFIG when we re-read. */
  for (up = hash_bucket(name), crecp = *up; crecp; crecp = tmp)
    {
      tmp = crecp->hash_next;

      if (!is_outdated_cname_pointer(crecp) &&
	  (crecp->flags & F_FORWARD) &&
	  (crecp->flags & type) &&
	  !(crecp->flags & (F_IPV4 | F_IPV6 | F_CNAME | F_SRV | F_DNSKEY | F_DS)) && 
	  hostname_isequal(name, cache_get_name(crecp)))
	{
	  *up = crecp->hash_next;
#ifdef HAVE_DHCP
	  if (type & F_DHCP)
	    {
	      crecp->next = dhcp_spare;
	      dhcp_spare = crecp;
	    }
	  else
#endif
	    free(crecp);
	  break;
	}
      else
	 up = &crecp->hash_next;
    }
     
  while ((name = strchr(name, '.')))
    {
      name++;

      /* Look for one existing, don't need another */
      for (crecp = *hash_bucket(name); crecp; crecp = crecp->hash_next)
	if (!is_outdated_cname_pointer(crecp) &&
	    (crecp->flags & F_FORWARD) &&
	    (crecp->flags & type) &&
	    hostname_isequal(name, cache_get_name(crecp)))
	  break;
      
      if (crecp)
	{
	  /* If the new name expires later, transfer that time to
	     empty non-terminal entry. */
	  if (!(crecp->flags & F_IMMORTAL))
	    {
	      if (source->flags & F_IMMORTAL)
		crecp->flags |= F_IMMORTAL;
	      else if (difftime(crecp->ttd, source->ttd) < 0)
		crecp->ttd = source->ttd;
	    }
	  continue;
	}
      
#ifdef HAVE_DHCP
      if ((source->flags & F_DHCP) && dhcp_spare)
	{
	  crecp = dhcp_spare;
	  dhcp_spare = dhcp_spare->next;
	}
      else
#endif
	crecp = whine_malloc(SIZEOF_POINTER_CREC);

      if (crecp)
	{
	  crecp->flags = (source->flags | F_NAMEP) & ~(F_IPV4 | F_IPV6 | F_CNAME | F_SRV | F_DNSKEY | F_DS | F_REVERSE);
	  if (!(crecp->flags & F_IMMORTAL))
	    crecp->ttd = source->ttd;
	  crecp->name.namep = name;
	  
	  cache_hash(crecp);
	}
    }
}

#ifndef NO_ID
/**
 * @brief Generate cache statistics for DNS TXT record response
 * 
 * @detailed Formats cache and query statistics as TXT record data based on t->stat type.
 * Statistics include: TXT_STAT_CACHESIZE (cache size), TXT_STAT_INSERTS (insertions count),
 * TXT_STAT_EVICTIONS (live freed count), TXT_STAT_MISSES (forwarded queries), TXT_STAT_HITS
 * (local answered), TXT_STAT_AUTH (authoritative answered if HAVE_AUTH), TXT_STAT_SERVERS
 * (per-upstream-server query counts and failures). TXT_STAT_SERVERS aggregates statistics
 * for duplicate server addresses (same IP:port) and dynamically expands buffer if needed.
 * Sets t->txt to formatted buffer and t->len to data length. Returns 1 on success, 0 on
 * memory allocation failure.
 * 
 * @param t Pointer to txt_record structure with stat field specifying statistic type
 * 
 * @return 1 on success, 0 on memory allocation failure
 * 
 * @note Uses static buffer (initial size 60 bytes), persists across calls
 * @note Buffer automatically expands for TXT_STAT_SERVERS if needed
 * @note TXT_STAT_SERVERS format: "IP#port queries failed_queries" per line
 * @note Aggregates statistics for servers with identical sockaddr
 * @note Uses SERV_MARK flag temporarily for deduplication
 * @note First byte of buff is length byte (DNS TXT record format)
 * 
 * @warning Static buffer shared across calls, not thread-safe
 * @warning TXT_STAT_AUTH only available if HAVE_AUTH defined
 * 
 * @see dump_cache() for logging statistics to syslog
 * @see struct txt_record for TXT_STAT_* constants
 * 
 * EXAMPLE USAGE:
 * @code
 * struct txt_record t;
 * t.stat = TXT_STAT_CACHESIZE;
 * if (cache_make_stat(&t))
 *   // t.txt now contains "100" (daemon->cachesize = 100)
 * @endcode
 * 
 * RFC COMPLIANCE: Generates DNS TXT record data per RFC 1035
 * 
 * SIDE EFFECTS:
 * - Allocates/expands static buffer on first call or if insufficient size
 * - Modifies serv->flags (SERV_MARK) temporarily for TXT_STAT_SERVERS
 * - Sets t->txt and t->len
 * 
 * THREAD SAFETY: Not thread-safe (uses static buffer, single-process event-driven architecture)
 */
int cache_make_stat(struct txt_record *t)
{ 
  static char *buff = NULL;
  static int bufflen = 60;
  int len;
  struct server *serv, *serv1;
  char *p;

  if (!buff && !(buff = whine_malloc(60)))
    return 0;

  p = buff;
  
  switch (t->stat)
    {
    case TXT_STAT_CACHESIZE:
      sprintf(buff+1, "%d", daemon->cachesize);
      break;

    case TXT_STAT_INSERTS:
      sprintf(buff+1, "%d", daemon->metrics[METRIC_DNS_CACHE_INSERTED]);
      break;

    case TXT_STAT_EVICTIONS:
      sprintf(buff+1, "%d", daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
      break;

    case TXT_STAT_MISSES:
      sprintf(buff+1, "%u", daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]);
      break;

    case TXT_STAT_HITS:
      sprintf(buff+1, "%u", daemon->metrics[METRIC_DNS_LOCAL_ANSWERED]);
      break;

#ifdef HAVE_AUTH
    case TXT_STAT_AUTH:
      sprintf(buff+1, "%u", daemon->metrics[METRIC_DNS_AUTH_ANSWERED]);
      break;
#endif

    case TXT_STAT_SERVERS:
      /* sum counts from different records for same server */
      for (serv = daemon->servers; serv; serv = serv->next)
	serv->flags &= ~SERV_MARK;
      
      for (serv = daemon->servers; serv; serv = serv->next)
	if (!(serv->flags & SERV_MARK))
	  {
	    char *new, *lenp;
	    int port, newlen, bytes_avail, bytes_needed;
	    unsigned int queries = 0, failed_queries = 0;
	    for (serv1 = serv; serv1; serv1 = serv1->next)
	      if (!(serv1->flags & SERV_MARK) && sockaddr_isequal(&serv->addr, &serv1->addr))
		{
		  serv1->flags |= SERV_MARK;
		  queries += serv1->queries;
		  failed_queries += serv1->failed_queries;
		}
	    port = prettyprint_addr(&serv->addr, daemon->addrbuff);
	    lenp = p++; /* length */
	    bytes_avail = bufflen - (p - buff );
	    bytes_needed = snprintf(p, bytes_avail, "%s#%d %u %u", daemon->addrbuff, port, queries, failed_queries);
	    if (bytes_needed >= bytes_avail)
	      {
		/* expand buffer if necessary */
		newlen = bytes_needed + 1 + bufflen - bytes_avail;
		if (!(new = whine_malloc(newlen)))
		  return 0;
		memcpy(new, buff, bufflen);
		free(buff);
		p = new + (p - buff);
		lenp = p - 1;
		buff = new;
		bufflen = newlen;
		bytes_avail =  bufflen - (p - buff );
		bytes_needed = snprintf(p, bytes_avail, "%s#%d %u %u", daemon->addrbuff, port, queries, failed_queries);
	      }
	    *lenp = bytes_needed;
	    p += bytes_needed;
	  }
      t->txt = (unsigned char *)buff;
      t->len = p - buff;

      return 1;
    }
  
  len = strlen(buff+1);
  t->txt = (unsigned char *)buff;
  t->len = len + 1;
  *buff = len;
  return 1;
}
#endif

/* There can be names in the cache containing control chars, don't 
   mess up logging or open security holes. */
static char *sanitise(char *name)
{
  unsigned char *r;
  if (name)
    for (r = (unsigned char *)name; *r; r++)
      if (!isprint((int)*r))
	return "<name unprintable>";

  return name;
}


/**
 * @brief Dump comprehensive cache statistics and contents to syslog
 * 
 * @detailed Logs cache statistics and full cache dump to syslog at LOG_INFO level. Triggered
 * by SIGUSR1 signal. Logs: (1) current time, (2) cache size and insertion/eviction metrics,
 * (3) forwarded vs locally answered query counts, (4) authoritative zone queries (if HAVE_AUTH),
 * (5) blockdata memory usage via blockdata_report(), (6) per-upstream-server query and failure
 * counts (aggregated by IP:port), (7) complete cache table if OPT_DEBUG or OPT_LOG enabled.
 * Cache dump shows: hostname, address/target, flags (4/6/C/V/S/K/F/R/I/D/N/X/H/C/V), expiry time
 * (absolute or seconds from now if HAVE_BROKEN_RTC), and record source (if F_HOSTS/F_CONFIG).
 * 
 * @param now Current time for expiry calculation
 * 
 * @return void
 * 
 * @note Typically invoked by SIGUSR1 signal handler
 * @note Cache dump only logged if OPT_DEBUG or OPT_LOG enabled
 * @note Aggregates server statistics for duplicate IP:port addresses using SERV_MARK
 * @note Flag abbreviations: 4=IPv4, 6=IPv6, C=CNAME, V=SRV, S=DS, K=DNSKEY, !=non-terminal,
 *       F=FORWARD, R=REVERSE, I=IMMORTAL, D=DHCP, N=NEG, X=NXDOMAIN, H=HOSTS, C=CONFIG, V=DNSSECOK
 * @note Expiry format depends on HAVE_BROKEN_RTC: seconds from now vs ctime() timestamp
 * @note Uses daemon->addrbuff and daemon->namebuff as formatting buffers
 * 
 * @see cache_make_stat() for TXT record statistics generation
 * @see blockdata_report() for blockdata memory statistics
 * @see record_source() for source name lookup
 * @see sanitise() for name sanitization
 * 
 * EXAMPLE USAGE:
 * @code
 * // In SIGUSR1 signal handler
 * dump_cache(time(NULL));
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific diagnostics)
 * 
 * SIDE EFFECTS:
 * - Writes extensive output to syslog at LOG_INFO level
 * - Modifies serv->flags (SERV_MARK) temporarily for aggregation
 * - Calls blockdata_report() which logs blockdata memory usage
 * 
 * THREAD SAFETY: Not thread-safe (single-process event-driven architecture)
 */
void dump_cache(time_t now)
{
  struct server *serv, *serv1;

  my_syslog(LOG_INFO, _("time %lu"), (unsigned long)now);
  my_syslog(LOG_INFO, _("cache size %d, %d/%d cache insertions re-used unexpired cache entries."), 
	    daemon->cachesize, daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED], daemon->metrics[METRIC_DNS_CACHE_INSERTED]);
  my_syslog(LOG_INFO, _("queries forwarded %u, queries answered locally %u"), 
	    daemon->metrics[METRIC_DNS_QUERIES_FORWARDED], daemon->metrics[METRIC_DNS_LOCAL_ANSWERED]);
#ifdef HAVE_AUTH
  my_syslog(LOG_INFO, _("queries for authoritative zones %u"), daemon->metrics[METRIC_DNS_AUTH_ANSWERED]);
#endif

  blockdata_report();

  /* sum counts from different records for same server */
  for (serv = daemon->servers; serv; serv = serv->next)
    serv->flags &= ~SERV_MARK;
  
  for (serv = daemon->servers; serv; serv = serv->next)
    if (!(serv->flags & SERV_MARK))
      {
	int port;
	unsigned int queries = 0, failed_queries = 0;
	for (serv1 = serv; serv1; serv1 = serv1->next)
	  if (!(serv1->flags & SERV_MARK) && sockaddr_isequal(&serv->addr, &serv1->addr))
	    {
	      serv1->flags |= SERV_MARK;
	      queries += serv1->queries;
	      failed_queries += serv1->failed_queries;
	    }
	port = prettyprint_addr(&serv->addr, daemon->addrbuff);
	my_syslog(LOG_INFO, _("server %s#%d: queries sent %u, retried or failed %u"), daemon->addrbuff, port, queries, failed_queries);
      }

  if (option_bool(OPT_DEBUG) || option_bool(OPT_LOG))
    {
      struct crec *cache ;
      int i;
      my_syslog(LOG_INFO, "Host                           Address                                  Flags      Expires                  Source");
      my_syslog(LOG_INFO, "------------------------------ ---------------------------------------- ---------- ------------------------ ------------");
    
      for (i=0; i<hash_size; i++)
	for (cache = hash_table[i]; cache; cache = cache->hash_next)
	  {
	    char *t = " ";
	    char *a = daemon->addrbuff, *p = daemon->namebuff, *n = cache_get_name(cache);
	    *a = 0;
	    if (strlen(n) == 0 && !(cache->flags & F_REVERSE))
	      n = "<Root>";
	    p += sprintf(p, "%-30.30s ", sanitise(n));
	    if ((cache->flags & F_CNAME) && !is_outdated_cname_pointer(cache))
	      a = sanitise(cache_get_cname_target(cache));
	    else if ((cache->flags & F_SRV) && !(cache->flags & F_NEG))
	      {
		int targetlen = cache->addr.srv.targetlen;
		ssize_t len = sprintf(a, "%u %u %u ", cache->addr.srv.priority,
				      cache->addr.srv.weight, cache->addr.srv.srvport);

		if (targetlen > (40 - len))
		  targetlen = 40 - len;
		blockdata_retrieve(cache->addr.srv.target, targetlen, a + len);
		a[len + targetlen] = 0;		
	      }
#ifdef HAVE_DNSSEC
	    else if (cache->flags & F_DS)
	      {
		if (!(cache->flags & F_NEG))
		  sprintf(a, "%5u %3u %3u", cache->addr.ds.keytag,
			  cache->addr.ds.algo, cache->addr.ds.digest);
	      }
	    else if (cache->flags & F_DNSKEY)
	      sprintf(a, "%5u %3u %3u", cache->addr.key.keytag,
		      cache->addr.key.algo, cache->addr.key.flags);
#endif
	    else if (!(cache->flags & F_NEG) || !(cache->flags & F_FORWARD))
	      { 
		a = daemon->addrbuff;
		if (cache->flags & F_IPV4)
		  inet_ntop(AF_INET, &cache->addr, a, ADDRSTRLEN);
		else if (cache->flags & F_IPV6)
		  inet_ntop(AF_INET6, &cache->addr, a, ADDRSTRLEN);
	      }

	    if (cache->flags & F_IPV4)
	      t = "4";
	    else if (cache->flags & F_IPV6)
	      t = "6";
	    else if (cache->flags & F_CNAME)
	      t = "C";
	    else if (cache->flags & F_SRV)
	      t = "V";
#ifdef HAVE_DNSSEC
	    else if (cache->flags & F_DS)
	      t = "S";
	    else if (cache->flags & F_DNSKEY)
	      t = "K";
#endif
	    else /* non-terminal */
	      t = "!";

	    p += sprintf(p, "%-40.40s %s%s%s%s%s%s%s%s%s%s ", a, t,
			 cache->flags & F_FORWARD ? "F" : " ",
			 cache->flags & F_REVERSE ? "R" : " ",
			 cache->flags & F_IMMORTAL ? "I" : " ",
			 cache->flags & F_DHCP ? "D" : " ",
			 cache->flags & F_NEG ? "N" : " ",
			 cache->flags & F_NXDOMAIN ? "X" : " ",
			 cache->flags & F_HOSTS ? "H" : " ",
			 cache->flags & F_CONFIG ? "C" : " ",
			 cache->flags & F_DNSSECOK ? "V" : " ");
#ifdef HAVE_BROKEN_RTC
	    p += sprintf(p, "%-24lu", cache->flags & F_IMMORTAL ? 0: (unsigned long)(cache->ttd - now));
#else
	    p += sprintf(p, "%-24.24s", cache->flags & F_IMMORTAL ? "" : ctime(&(cache->ttd)));
#endif
	    if(cache->flags & (F_HOSTS | F_CONFIG) && cache->uid > 0)
		p += sprintf(p, " %s", record_source(cache->uid));

	    my_syslog(LOG_INFO, "%s", daemon->namebuff);
	  }
    }
}

/**
 * @brief Convert cache record source UID to human-readable source name
 * 
 * @detailed Translates cache entry UID (stored in crec->uid) to descriptive source string
 * for logging and diagnostics. Maps special sentinel values (SRC_CONFIG, SRC_HOSTS) to
 * "config" and HOSTSFILE (typically "/etc/hosts"), iterates daemon->addn_hosts list for
 * additional hosts files (--addn-hosts), and daemon->dynamic_dirs for inotify-watched
 * directories. Returns "<unknown>" if index doesn't match any known source.
 * Used by log_query() and conflict warning messages to identify where cache entry originated.
 * 
 * @param index Cache record UID from crec->uid (unique identifier for source)
 * 
 * @return String pointer to source name:
 * @retval "config" if index == SRC_CONFIG (static configuration)
 * @retval HOSTSFILE if index == SRC_HOSTS (typically "/etc/hosts")
 * @retval filename if index matches entry in daemon->addn_hosts or daemon->dynamic_dirs
 * @retval "<unknown>" if index doesn't match any known source
 * 
 * @note Return value is pointer to static string or hostsfile struct member (not allocated)
 * @note Thread-safe for read-only access to daemon structures
 * @note Used for logging only, not for cache logic
 * 
 * @see SRC_CONFIG and SRC_HOSTS constants in dnsmasq.h
 * @see struct hostsfile in dnsmasq.h
 * @see daemon->addn_hosts for additional hosts file list
 * @see daemon->dynamic_dirs for inotify-watched directories (if HAVE_INOTIFY)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *cache = cache_find_by_name(NULL, "example.com", 0, F_IPV4);
 * if (cache)
 *   my_syslog(LOG_INFO, "Found in %s", record_source(cache->uid));
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific diagnostics)
 * 
 * SIDE EFFECTS: None (read-only function)
 * 
 * THREAD SAFETY: Thread-safe (read-only access to static structures)
 */
char *record_source(unsigned int index)
{
  struct hostsfile *ah;

  if (index == SRC_CONFIG)
    return "config";
  else if (index == SRC_HOSTS)
    return HOSTSFILE;

  for (ah = daemon->addn_hosts; ah; ah = ah->next)
    if (ah->index == index)
      return ah->fname;

#ifdef HAVE_INOTIFY
  for (ah = daemon->dynamic_dirs; ah; ah = ah->next)
     if (ah->index == index)
       return ah->fname;
#endif

  return "<unknown>";
}

static char *querystr(char *desc, unsigned short type)
{
  unsigned int i;
  int len = 10; /* strlen("type=xxxxx") */
  const char *types = NULL;
  static char *buff = NULL;
  static int bufflen = 0;

  for (i = 0; i < (sizeof(typestr)/sizeof(typestr[0])); i++)
    if (typestr[i].type == type)
      {
	types = typestr[i].name;
	len = strlen(types);
	break;
      }

  if (desc)
    {
       len += 2; /* braces */
       len += strlen(desc);
    }
  len++; /* terminator */
  
  if (!buff || bufflen < len)
    {
      if (buff)
	free(buff);
      else if (len < 20)
	len = 20;
      
      buff = whine_malloc(len);
      bufflen = len;
    }

  if (buff)
    {
      if (desc)
	{
	  if (types)
	    sprintf(buff, "%s[%s]", desc, types);
	  else
	    sprintf(buff, "%s[type=%d]", desc, type);
	}
      else
	{
	  if (types)
	    sprintf(buff, "<%s>", types);
	  else
	    sprintf(buff, "<type=%d>", type);
	}
    }
  
  return buff ? buff : "";
}

static char *edestr(int ede)
{
  switch (ede)
    {
    case EDE_OTHER:                       return "other";
    case EDE_USUPDNSKEY:                  return "unsupported DNSKEY algorithm";
    case EDE_USUPDS:                      return "unsupported DS digest";
    case EDE_STALE:                       return "stale answer";
    case EDE_FORGED:                      return "forged";
    case EDE_DNSSEC_IND:                  return "DNSSEC indeterminate";
    case EDE_DNSSEC_BOGUS:                return "DNSSEC bogus";
    case EDE_SIG_EXP:                     return "DNSSEC signature expired";
    case EDE_SIG_NYV:                     return "DNSSEC sig not yet valid";
    case EDE_NO_DNSKEY:                   return "DNSKEY missing";
    case EDE_NO_RRSIG:                    return "RRSIG missing";
    case EDE_NO_ZONEKEY:                  return "no zone key bit set";
    case EDE_NO_NSEC:                     return "NSEC(3) missing";
    case EDE_CACHED_ERR:                  return "cached error";
    case EDE_NOT_READY:                   return "not ready";
    case EDE_BLOCKED:                     return "blocked";
    case EDE_CENSORED:                    return "censored";
    case EDE_FILTERED:                    return "filtered";
    case EDE_PROHIBITED:                  return "prohibited";
    case EDE_STALE_NXD:                   return "stale NXDOMAIN";
    case EDE_NOT_AUTH:                    return "not authoritative";
    case EDE_NOT_SUP:                     return "not supported";
    case EDE_NO_AUTH:                     return "no reachable authority";
    case EDE_NETERR:                      return "network error";
    case EDE_INVALID_DATA:                return "invalid data";
    default:                              return "unknown";
    }
}

/**
 * @brief Log DNS query or response to syslog in human-readable format
 * 
 * @detailed Formats and logs DNS query/response events to syslog at LOG_INFO level if OPT_LOG
 * enabled. Constructs log message with source (config/DHCP/hosts/cached/forwarded/reply/etc.),
 * name (sanitized DNS name), verb (is/from/to), and destination (IP address, RCODE, NXDOMAIN,
 * NODATA, CNAME, SRV, etc.). Handles special cases: F_REVERSE (PTR), F_NEG (negative cache),
 * F_KEYTAG (DNSSEC), F_RCODE (error responses), F_IPSET (ipset/nftset add). If OPT_EXTRALOG
 * enabled, includes source address/port and query ID. Adds EDE (Extended DNS Error) if present.
 * Sanitizes name to prevent log injection attacks. Returns immediately if OPT_LOG disabled.
 * 
 * @param flags Operation flags (F_FORWARD, F_REVERSE, F_NEG, F_NXDOMAIN, F_IPV4, F_IPV6,
 *              F_CNAME, F_SRV, F_CONFIG, F_DHCP, F_HOSTS, F_UPSTREAM, F_SERVER, F_QUERY,
 *              F_AUTH, F_DNSSEC, F_KEYTAG, F_RCODE, F_IPSET, F_SECSTAT, F_NOEXTRA)
 * @param name DNS name being queried/answered (e.g., "example.com"), may be NULL
 * @param addr Address data (IPv4/IPv6 addr, or log.keytag/algo/digest, or log.rcode/ede), may be NULL
 * @param arg Context-dependent: query type string, source name, ipset name, etc.
 * @param type Query type number (A=1, AAAA=28, etc.) or port number if F_SERVER, or 0/1 for ipset/nftset
 * 
 * @return void
 * 
 * @note Returns immediately without logging if OPT_LOG disabled
 * @note Sanitizes name with sanitise() to prevent control char injection
 * @note F_KEYTAG: addr->log.keytag/algo/digest formatted with arg as sprintf format string
 * @note F_RCODE: Translates SERVFAIL/REFUSED/NOTIMP to text, shows EDE if addr->log.ede != EDE_UNSET
 * @note F_REVERSE: Swaps name and destination (PTR query logging)
 * @note F_NEG: Shows NXDOMAIN or NODATA-IPv4/NODATA-IPv6/NODATA depending on flags
 * @note OPT_EXTRALOG: Adds source IP:port and query ID to log message
 * @note Uses daemon->addrbuff/addrbuff2 as temporary formatting buffers
 * 
 * @warning Assumes daemon->log_display_id set if OPT_EXTRALOG enabled
 * @warning Assumes daemon->log_source_addr set if OPT_EXTRALOG and !F_NOEXTRA
 * 
 * @see sanitise() for name sanitization
 * @see querystr() for query type to string conversion
 * @see edestr() for EDE code to description
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * inet_pton(AF_INET, "192.0.2.1", &addr.addr4);
 * log_query(F_FORWARD | F_IPV4, "example.com", &addr, "query[A]", T_A);
 * // Logs: "query[A] example.com from 192.0.2.1"
 * @endcode
 * 
 * RFC COMPLIANCE: Logs DNS operations per RFC 1035 concepts
 * 
 * SIDE EFFECTS:
 * - Writes to syslog at LOG_INFO level (if OPT_LOG enabled)
 * - Modifies daemon->addrbuff and daemon->addrbuff2 (temporary formatting)
 * 
 * THREAD SAFETY: Not thread-safe (uses daemon globals, single-process event-driven architecture)
 */
void log_query(unsigned int flags, char *name, union all_addr *addr, char *arg, unsigned short type)
{
  char *source, *dest = arg;
  char *verb = "is";
  char *extra = "";
  char portstring[7]; /* space for #<portnum> */
  
  if (!option_bool(OPT_LOG))
    return;

  /* build query type string if requested */
  if (!(flags & (F_SERVER | F_IPSET)) && type > 0)
    arg = querystr(arg, type);

#ifdef HAVE_DNSSEC
  if ((flags & F_DNSSECOK) && option_bool(OPT_EXTRALOG))
    extra = " (DNSSEC signed)";
#endif

  name = sanitise(name);

  if (addr)
    {
      dest = daemon->addrbuff;

      if (flags & F_KEYTAG)
	sprintf(daemon->addrbuff, arg, addr->log.keytag, addr->log.algo, addr->log.digest);
      else if (flags & F_RCODE)
	{
	  unsigned int rcode = addr->log.rcode;

	  if (rcode == SERVFAIL)
	    dest = "SERVFAIL";
	  else if (rcode == REFUSED)
	    dest = "REFUSED";
	  else if (rcode == NOTIMP)
	    dest = "not implemented";
	  else
	    sprintf(daemon->addrbuff, "%u", rcode);

	  if (addr->log.ede != EDE_UNSET)
	    {
	      extra = daemon->addrbuff;
	      sprintf(extra, " (EDE: %s)", edestr(addr->log.ede));
	    }
	}
      else if (flags & (F_IPV4 | F_IPV6))
	{
	  inet_ntop(flags & F_IPV4 ? AF_INET : AF_INET6,
		    addr, daemon->addrbuff, ADDRSTRLEN);
	  if ((flags & F_SERVER) && type != NAMESERVER_PORT)
	    {
	      extra = portstring;
	      sprintf(portstring, "#%u", type);
	    }
	}
      else
	dest = arg;
    }

  if (flags & F_REVERSE)
    {
      dest = name;
      name = daemon->addrbuff;
    }
  
  if (flags & F_NEG)
    {
      if (flags & F_NXDOMAIN)
	dest = "NXDOMAIN";
      else
	{      
	  if (flags & F_IPV4)
	    dest = "NODATA-IPv4";
	  else if (flags & F_IPV6)
	    dest = "NODATA-IPv6";
	  else
	    dest = "NODATA";
	}
    }
  else if (flags & F_CNAME)
    dest = "<CNAME>";
  else if (flags & F_SRV)
    dest = "<SRV>";
  else if (flags & F_RRNAME)
    dest = arg;
    
  if (flags & F_CONFIG)
    source = "config";
  else if (flags & F_DHCP)
    source = "DHCP";
  else if (flags & F_HOSTS)
    source = arg;
  else if (flags & F_UPSTREAM)
    source = "reply";
  else if (flags & F_SECSTAT)
    {
      if (addr && addr->log.ede != EDE_UNSET && option_bool(OPT_EXTRALOG))
	{
	  extra = daemon->addrbuff;
	  sprintf(extra, " (EDE: %s)", edestr(addr->log.ede));
	}
      source = "validation";
      dest = arg;
    }
  else if (flags & F_AUTH)
    source = "auth";
   else if (flags & F_DNSSEC)
    {
      source = arg;
      verb = "to";
    }
   else if (flags & F_SERVER)
    {
      source = "forwarded";
      verb = "to";
    }
  else if (flags & F_QUERY)
    {
      source = arg;
      verb = "from";
    }
  else if (flags & F_IPSET)
    {
      source = type ? "ipset add" : "nftset add";
      dest = name;
      name = arg;
      verb = daemon->addrbuff;
    }
  else
    source = "cached";
  
  if (name && !name[0])
    name = ".";

  if (option_bool(OPT_EXTRALOG))
    {
      if (flags & F_NOEXTRA)
	my_syslog(LOG_INFO, "%u %s %s %s %s%s", daemon->log_display_id, source, name, verb, dest, extra);
      else
	{
	   int port = prettyprint_addr(daemon->log_source_addr, daemon->addrbuff2);
	   my_syslog(LOG_INFO, "%u %s/%u %s %s %s %s%s", daemon->log_display_id, daemon->addrbuff2, port, source, name, verb, dest, extra);
	}
    }
  else
    my_syslog(LOG_INFO, "%s %s %s %s%s", source, name, verb, dest, extra);
}
