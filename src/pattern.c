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
 * @file pattern.c
 * @brief Pattern matching utilities for DNS name validation and wildcard matching
 *
 * DETAILED PURPOSE:
 * This file implements DNS name validation according to RFC 1123 specifications and
 * provides glob-style pattern matching capabilities specifically designed for connection
 * tracking integration. The validation functions ensure DNS names conform to RFC 1123
 * requirements: 1-253 characters total length, labels of 1-63 characters, consisting of
 * alphanumeric characters and hyphens (not starting or ending with hyphens), with fully
 * qualified domain names containing at least two labels where the final label is not
 * fully numeric and not the "local" pseudo-TLD.
 *
 * The pattern matching functionality extends basic DNS name validation with wildcard
 * support, allowing the asterisk (*) character to match zero or more characters within
 * a label boundary. Wildcards never cross label boundaries (dots), enabling fine-grained
 * matching patterns like "*.example.com" (matches "api.example.com" but not 
 * "api.us.example.com"). Up to two wildcards per label are permitted, with the constraint
 * that patterns must end with at least two literal (non-wildcard) labels for security.
 *
 * All functionality in this file is conditionally compiled under HAVE_CONNTRACK and is
 * used exclusively for pattern-based connection marking in the connection tracking subsystem.
 *
 * KEY RESPONSIBILITIES:
 * - is_valid_dns_name() - Validates DNS names against RFC 1123 specifications
 * - is_valid_dns_name_pattern() - Validates DNS name patterns with wildcard support
 * - is_dns_name_matching_pattern() - Matches DNS names against wildcard patterns
 * - is_string_matching_glob_pattern() - Internal glob matching algorithm implementation
 *
 * DEPENDENCIES:
 * - Includes: dnsmasq.h (for my_syslog, type definitions, and macros)
 * - Called by: conntrack.c (for pattern-based connection marking configuration)
 * - Calls: my_syslog() for debug logging and error reporting
 *
 * DATA STRUCTURES:
 * - No custom data structures defined (operates on C strings)
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_CONNTRACK: This entire file is excluded from compilation if HAVE_CONNTRACK is
 *   not defined. When enabled, provides DNS name pattern matching for netfilter conntrack
 *   mark assignment based on resolved DNS names.
 *
 * THREADING/CONCURRENCY:
 * All functions in this file are re-entrant and safe for use in dnsmasq's single-process
 * event-driven architecture. Functions operate only on provided parameters without accessing
 * global state (except for logging via my_syslog). The ASSERT macro logs assertion failures
 * but does not terminate execution, maintaining operational stability.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_CONNTRACK

#define LOG(...) \
  do { \
    my_syslog(LOG_DEBUG, __VA_ARGS__); \
  } while (0)

#define ASSERT(condition) \
  do { \
    if (!(condition)) \
      my_syslog(LOG_ERR, _("[pattern.c:%d] Assertion failure: %s"), __LINE__, #condition); \
  } while (0)

/**
 * @brief Match string against glob pattern with wildcard support
 *
 * @detailed
 * Implements efficient glob pattern matching allowing '*' wildcards that match zero or
 * more characters. The algorithm performs case-insensitive matching by converting both
 * value and pattern characters to uppercase during comparison. Uses a backtracking
 * approach optimized for common matching scenarios, as described by Russ Cox in
 * "Glob Matching Can Be Simple And Fast Too" (https://research.swtch.com/glob).
 * The implementation handles multiple wildcards efficiently without exponential
 * time complexity by maintaining restart positions for backtracking.
 *
 * @param value String value to match (must not be NULL)
 * @param num_value_bytes Length of the string value in bytes
 * @param pattern Glob pattern containing optional '*' wildcards (must not be NULL)
 * @param num_pattern_bytes Length of the glob pattern in bytes
 *
 * @return 1 if the value matches the glob pattern
 * @retval 1 Value successfully matches pattern (including all wildcards)
 * @retval 0 Value does not match pattern
 *
 * @note Matching is case-insensitive: lowercase letters are converted to uppercase
 *       during comparison. Wildcards match greedily but use backtracking to find
 *       valid matches. This function is internal to pattern.c and called exclusively
 *       by is_dns_name_matching_pattern() for label-by-label matching.
 * @note Algorithm attribution: Based on Russ Cox's simplified glob matching approach
 *       which avoids recursive backtracking and exponential time complexity.
 *
 * @warning Both value and pattern pointers must be non-NULL; violation triggers
 *          ASSERT logging but continues execution. Undefined behavior if pointers
 *          are NULL and assertions are disabled.
 * @warning The num_value_bytes and num_pattern_bytes must accurately reflect the
 *          lengths of their respective strings to avoid buffer overruns.
 *
 * @see is_dns_name_matching_pattern() which calls this function for each DNS label pair
 *
 * EXAMPLE USAGE:
 * @code
 * const char *name = "api-prod";
 * const char *pattern = "api-*";
 * if (is_string_matching_glob_pattern(name, 8, pattern, 5))
 *   LOG("Match found");
 * @endcode
 *
 * THREAD SAFETY:
 * This function is re-entrant and thread-safe. It operates only on the provided
 * parameters using local stack variables without accessing any global state or
 * modifying the input parameters.
 */
static int is_string_matching_glob_pattern(
  const char *value,
  size_t num_value_bytes,
  const char *pattern,
  size_t num_pattern_bytes)
{
  ASSERT(value);
  ASSERT(pattern);
  
  size_t value_index = 0;
  size_t next_value_index = 0;
  size_t pattern_index = 0;
  size_t next_pattern_index = 0;
  while (value_index < num_value_bytes || pattern_index < num_pattern_bytes)
    {
      if (pattern_index < num_pattern_bytes)
	{
	  char pattern_character = pattern[pattern_index];
	  if ('a' <= pattern_character && pattern_character <= 'z')
	    pattern_character -= 'a' - 'A';
	  if (pattern_character == '*')
	    {
	      /* zero-or-more-character wildcard */
	      /* Try to match at value_index, otherwise restart at value_index + 1 next. */
	      next_pattern_index = pattern_index;
	      pattern_index++;
	      if (value_index < num_value_bytes)
		next_value_index = value_index + 1;
	      else
		next_value_index = 0;
	      continue;
	    }
	  else
	    {
	      /* ordinary character */
	      if (value_index < num_value_bytes)
	        {
		  char value_character = value[value_index];
		  if ('a' <= value_character && value_character <= 'z')
		    value_character -= 'a' - 'A';
		  if (value_character == pattern_character)
		    {
		      pattern_index++;
		      value_index++;
		      continue;
		    }
		}
	    }
	}
      if (next_value_index)
	{
	  pattern_index = next_pattern_index;
	  value_index = next_value_index;
	  continue;
	}
      return 0;
    }
  return 1;
}

/**
 * @brief Validate DNS name conformance to RFC 1123
 *
 * @detailed
 * Validates that a string represents a properly formatted DNS name according to RFC 1123
 * specifications. The algorithm iterates through the string character-by-character,
 * validating label boundaries, character constraints, and overall structure. Each label
 * is validated for length (1-63 characters), valid character set (alphanumeric and hyphen),
 * and proper start/end characters (no leading or trailing hyphens). The complete name
 * must be 1-253 characters, fully qualified (minimum 2 labels), with a non-numeric
 * final label that is not the "local" pseudo-TLD.
 *
 * @param value String value to validate as DNS name (must not be NULL)
 *
 * @return 1 if the string is a valid RFC 1123 DNS name
 * @retval 1 Value represents a valid DNS name meeting all RFC 1123 requirements
 * @retval 0 Value is invalid (logs specific reason via my_syslog)
 *
 * @note RFC 1123 Requirements enforced:
 *       - Total length: 1-253 characters
 *       - Label length: 1-63 characters each
 *       - Character set: ASCII letters (a-z, A-Z), digits (0-9), hyphen (-)
 *       - Label constraints: No leading or trailing hyphens
 *       - Minimum structure: At least 2 labels (fully qualified domain name)
 *       - Final label: Not fully numeric (prevents IP address confusion)
 *       - Pseudo-TLD: "local" pseudo-TLD is rejected (case-insensitive)
 * @note Empty labels (consecutive dots or leading/trailing dots) are rejected
 * @note Examples of valid names: "example.com", "api.example.com", "my-server.example.org"
 * @note Examples of invalid names: "ipcamera" (single label), "ipcamera.local" (local TLD),
 *       "8.8.8.8" (numeric final label), "example..com" (empty label), "-test.com" (hyphen start)
 *
 * @warning Value pointer must be non-NULL; violation triggers ASSERT logging. Behavior
 *          is undefined if value is NULL and assertions are disabled.
 *
 * @see is_valid_dns_name_pattern() for wildcard pattern validation
 * @see RFC 1123 Section 2.1 "Host Names and Numbers" for complete specification
 *
 * EXAMPLE USAGE:
 * @code
 * const char *name1 = "example.com";
 * const char *name2 = "8.8.8.8";
 * if (is_valid_dns_name(name1))
 *   LOG("Valid DNS name");  // This executes
 * if (is_valid_dns_name(name2))
 *   LOG("Valid DNS name");  // This does not execute (numeric final label)
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1123 Section 2.1 "Host Names and Numbers" with additional constraints
 * requiring fully qualified domain names (minimum 2 labels) and rejection of the "local"
 * pseudo-TLD commonly used for mDNS which should not be processed by DNS forwarders.
 *
 * SIDE EFFECTS:
 * Logs detailed validation failure reasons via my_syslog(LOG_DEBUG) including specific
 * invalid characters, empty labels, hyphen position violations, label length violations,
 * insufficient label count, numeric final labels, "local" pseudo-TLD detection, and
 * overall length violations.
 *
 * THREAD SAFETY:
 * This function is re-entrant and safe for use in single-process event-driven architecture.
 * Operates only on the provided parameter using local stack variables. Logging via
 * my_syslog is handled by dnsmasq's logging infrastructure.
 */
int is_valid_dns_name(const char *value)
{
  ASSERT(value);
  
  size_t num_bytes = 0;
  size_t num_labels = 0;
  const char *c, *label = NULL;
  int is_label_numeric = 1;
  for (c = value;; c++)
    {
      if (*c &&
	  *c != '-' && *c != '.' &&
	  (*c < '0' || *c > '9') &&
	  (*c < 'A' || *c > 'Z') &&
	  (*c < 'a' || *c > 'z'))
	{
	  LOG(_("Invalid DNS name: Invalid character %c."), *c);
	  return 0;
	}
      if (*c)
	num_bytes++;
      if (!label)
	{
	  if (!*c || *c == '.')
	    {
	      LOG(_("Invalid DNS name: Empty label."));
	      return 0;
	    }
	  if (*c == '-')
	    {
	      LOG(_("Invalid DNS name: Label starts with hyphen."));
	      return 0;
	    }
	  label = c;
	}
      if (*c && *c != '.')
	{
	  if (*c < '0' || *c > '9')
	    is_label_numeric = 0;
	}
      else
	{
	  if (c[-1] == '-')
	    {
	      LOG(_("Invalid DNS name: Label ends with hyphen."));
	      return 0;
	    }
	  size_t num_label_bytes = (size_t) (c - label);
	  if (num_label_bytes > 63)
	    {
	      LOG(_("Invalid DNS name: Label is too long (%zu)."), num_label_bytes);
	      return 0;
	    }
	  num_labels++;
	  if (!*c)
	    {
	      if (num_labels < 2)
		{
		  LOG(_("Invalid DNS name: Not enough labels (%zu)."), num_labels);
		  return 0;
		}
	      if (is_label_numeric)
		{
		  LOG(_("Invalid DNS name: Final label is fully numeric."));
		  return 0;
		}
	      if (num_label_bytes == 5 &&
		  (label[0] == 'l' || label[0] == 'L') &&
		  (label[1] == 'o' || label[1] == 'O') &&
		  (label[2] == 'c' || label[2] == 'C') &&
		  (label[3] == 'a' || label[3] == 'A') &&
		  (label[4] == 'l' || label[4] == 'L'))
		{
		  LOG(_("Invalid DNS name: \"local\" pseudo-TLD."));
		  return 0;
		}
	      if (num_bytes < 1 || num_bytes > 253)
		{
		  LOG(_("DNS name has invalid length (%zu)."), num_bytes);
		  return 0;
		}
	      return 1;
	    }
	  label = NULL;
	  is_label_numeric = 1;
	}
    }
}

/**
 * @brief Validate DNS name pattern with wildcard support
 *
 * @detailed
 * Validates that a string represents a properly formatted DNS name pattern according to
 * RFC 1123 DNS name requirements extended with wildcard support. The algorithm performs
 * similar validation to is_valid_dns_name() but additionally permits asterisk (*) wildcard
 * characters within labels. Wildcards are constrained to a maximum of two per label and
 * must not appear in the final two labels (security requirement to prevent overly broad
 * matching like "*.com"). Wildcards never match across label boundaries (dots), enabling
 * precise subdomain matching. The pattern length calculation excludes wildcard characters
 * when validating against the 253-character limit.
 *
 * @param value String value to validate as DNS name pattern (must not be NULL)
 *
 * @return 1 if the string is a valid DNS name pattern with proper wildcard constraints
 * @retval 1 Value represents a valid DNS pattern meeting all requirements
 * @retval 0 Value is invalid (logs specific reason via my_syslog)
 *
 * @note Wildcard Constraints:
 *       - Maximum 2 wildcards per label (e.g., "*-prod-*" is valid, "*-*-*" is not)
 *       - Wildcards never match dots (label boundaries)
 *       - Pattern must end with 2 literal labels (no wildcards in final two labels)
 *       - Wildcard characters excluded from 253-character length calculation
 * @note Inherits all RFC 1123 constraints from is_valid_dns_name():
 *       - Label length 1-63 characters (excluding wildcards)
 *       - Valid characters: alphanumeric, hyphen, asterisk
 *       - No leading/trailing hyphens in labels
 *       - Minimum 2 labels, non-numeric final label, no "local" pseudo-TLD
 * @note Valid pattern examples:
 *       - "*.example.com" (matches any single-label subdomain)
 *       - "video*.example.com" (matches video1, video-prod, etc.)
 *       - "*-prod-*.example.com" (matches app1-prod-east, api-prod-west, etc.)
 *       - "api*.*.example.com" (matches api1.us.example.com, api-test.staging.example.com)
 * @note Invalid pattern examples:
 *       - "*.com" (wildcard in final two labels)
 *       - "*" (single label, wildcard in final)
 *       - "***test.example.com" (more than 2 wildcards per label)
 *       - "ipcamera.local" (local pseudo-TLD)
 *
 * @warning Value pointer must be non-NULL; violation triggers ASSERT logging. Behavior
 *          is undefined if value is NULL and assertions are disabled.
 *
 * @see is_valid_dns_name() for base DNS name validation without wildcards
 * @see is_dns_name_matching_pattern() for matching names against validated patterns
 *
 * EXAMPLE USAGE:
 * @code
 * const char *pattern1 = "*.example.com";
 * const char *pattern2 = "*.com";
 * if (is_valid_dns_name_pattern(pattern1))
 *   LOG("Valid pattern");  // This executes
 * if (is_valid_dns_name_pattern(pattern2))
 *   LOG("Valid pattern");  // This does not execute (wildcard in final two labels)
 * @endcode
 *
 * RFC COMPLIANCE:
 * Based on RFC 1123 Section 2.1 with wildcard extensions. Wildcard matching semantics
 * are not defined by RFC 1123 but follow common glob-style pattern conventions restricted
 * to DNS label boundaries for security. The two-literal-label suffix requirement prevents
 * overly broad patterns that could match entire TLDs.
 *
 * SIDE EFFECTS:
 * Logs detailed validation failure reasons via my_syslog(LOG_DEBUG) including invalid
 * characters, wildcard constraint violations (>2 per label, wildcards in final two labels),
 * empty labels, hyphen position errors, label length violations, insufficient labels,
 * numeric final labels, "local" pseudo-TLD, and length violations.
 *
 * THREAD SAFETY:
 * This function is re-entrant and safe for single-process event-driven architecture.
 * Operates only on the provided parameter using local stack variables without global
 * state access beyond logging.
 */
int is_valid_dns_name_pattern(const char *value)
{
  ASSERT(value);
  
  size_t num_bytes = 0;
  size_t num_labels = 0;
  const char *c, *label = NULL;
  int is_label_numeric = 1;
  size_t num_wildcards = 0;
  int previous_label_has_wildcard = 1;
  for (c = value;; c++)
    {
      if (*c &&
	  *c != '*' && /* Wildcard. */
	  *c != '-' && *c != '.' &&
	  (*c < '0' || *c > '9') &&
	  (*c < 'A' || *c > 'Z') &&
	  (*c < 'a' || *c > 'z'))
	{
	  LOG(_("Invalid DNS name pattern: Invalid character %c."), *c);
	  return 0;
	}
      if (*c && *c != '*')
	num_bytes++;
      if (!label)
	{
	  if (!*c || *c == '.')
	    {
	      LOG(_("Invalid DNS name pattern: Empty label."));
	      return 0;
	    }
	  if (*c == '-')
	    {
	      LOG(_("Invalid DNS name pattern: Label starts with hyphen."));
	      return 0;
	    }
	  label = c;
	}
      if (*c && *c != '.')
	{
	  if (*c < '0' || *c > '9')
	    is_label_numeric = 0;
	  if (*c == '*')
	    {
	      if (num_wildcards >= 2)
		{
		  LOG(_("Invalid DNS name pattern: Wildcard character used more than twice per label."));
		  return 0;
		}
	      num_wildcards++;
	    }
	}
      else
	{
	  if (c[-1] == '-')
	    {
	      LOG(_("Invalid DNS name pattern: Label ends with hyphen."));
	      return 0;
	    }
	  size_t num_label_bytes = (size_t) (c - label) - num_wildcards;
	  if (num_label_bytes > 63)
	    {
	      LOG(_("Invalid DNS name pattern: Label is too long (%zu)."), num_label_bytes);
	      return 0;
	    }
	  num_labels++;
	  if (!*c)
	    {
	      if (num_labels < 2)
		{
		  LOG(_("Invalid DNS name pattern: Not enough labels (%zu)."), num_labels);
		  return 0;
		}
	      if (num_wildcards != 0 || previous_label_has_wildcard)
		{
		  LOG(_("Invalid DNS name pattern: Wildcard within final two labels."));
		  return 0;
		}
	      if (is_label_numeric)
		{
		  LOG(_("Invalid DNS name pattern: Final label is fully numeric."));
		  return 0;
		}
	      if (num_label_bytes == 5 &&
		  (label[0] == 'l' || label[0] == 'L') &&
		  (label[1] == 'o' || label[1] == 'O') &&
		  (label[2] == 'c' || label[2] == 'C') &&
		  (label[3] == 'a' || label[3] == 'A') &&
		  (label[4] == 'l' || label[4] == 'L'))
		{
		  LOG(_("Invalid DNS name pattern: \"local\" pseudo-TLD."));
		  return 0;
		}
	      if (num_bytes < 1 || num_bytes > 253)
		{
		  LOG(_("DNS name pattern has invalid length after removing wildcards (%zu)."), num_bytes);
		  return 0;
		}
	      return 1;
	    }
	    label = NULL;
	    is_label_numeric = 1;
	    previous_label_has_wildcard = num_wildcards != 0;
	    num_wildcards = 0;
	  }
    }
}

/**
 * @brief Match DNS name against wildcard pattern
 *
 * @detailed
 * Determines whether a DNS name matches a DNS name pattern by performing label-by-label
 * comparison from left to right. The algorithm splits both the name and pattern into
 * labels delimited by dots, then invokes is_string_matching_glob_pattern() for each
 * corresponding label pair. Matching succeeds only if all label pairs match and both
 * name and pattern have the same number of labels (complete traversal). This ensures
 * wildcards never match across label boundaries, providing precise subdomain matching
 * control for connection tracking mark assignment.
 *
 * @param name Valid DNS name to match (must pass is_valid_dns_name(), must not be NULL)
 * @param pattern Valid DNS name pattern (must pass is_valid_dns_name_pattern(), must not be NULL)
 *
 * @return 1 if the DNS name matches the pattern, 0 if no match
 * @retval 1 Name successfully matches pattern across all labels
 * @retval 0 Name does not match pattern (label mismatch or label count mismatch)
 *
 * @note Matching is performed label-by-label from left to right. Each label in the name
 *       is matched against the corresponding label in the pattern using case-insensitive
 *       glob matching. Wildcards in pattern labels match zero or more characters within
 *       that label only and never cross dot boundaries.
 * @note The function assumes both name and pattern have been pre-validated by their
 *       respective validation functions. ASSERT macros verify this precondition but do
 *       not prevent execution if assertions are disabled.
 * @note Matching examples:
 *       - "api.example.com" matches "*.example.com"
 *       - "api.us.example.com" does NOT match "*.example.com" (label count mismatch)
 *       - "video1.example.com" matches "video*.example.com"
 *       - "app1-prod-east.example.com" matches "*-prod-*.example.com"
 *
 * @warning Both name and pattern must be non-NULL and pre-validated. Violation of the
 *          non-NULL requirement triggers ASSERT logging. Passing invalid names or patterns
 *          that have not been validated via is_valid_dns_name() or is_valid_dns_name_pattern()
 *          results in undefined behavior, though ASSERT checks attempt to detect this.
 * @warning Behavior is undefined if name or pattern are invalid DNS names/patterns. Always
 *          validate inputs before calling this function.
 *
 * @see is_string_matching_glob_pattern() which performs the actual wildcard matching for each label
 * @see is_valid_dns_name() which should validate name parameter before calling
 * @see is_valid_dns_name_pattern() which should validate pattern parameter before calling
 *
 * EXAMPLE USAGE:
 * @code
 * const char *name = "api.example.com";
 * const char *pattern = "*.example.com";
 * if (is_valid_dns_name(name) && is_valid_dns_name_pattern(pattern)) {
 *   if (is_dns_name_matching_pattern(name, pattern))
 *     LOG("Match found");  // This executes
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * None. This function performs read-only operations on the provided parameters and
 * does not log, modify global state, or perform I/O operations. ASSERT macros may
 * log validation failures but do not alter function behavior.
 *
 * THREAD SAFETY:
 * This function is fully re-entrant and thread-safe. It operates exclusively on the
 * provided parameters using local stack variables without accessing any global state.
 * Can be safely called concurrently from multiple execution contexts.
 */
int is_dns_name_matching_pattern(const char *name, const char *pattern)
{
  ASSERT(name);
  ASSERT(is_valid_dns_name(name));
  ASSERT(pattern);
  ASSERT(is_valid_dns_name_pattern(pattern));
  
  const char *n = name;
  const char *p = pattern;
  
  do {
    const char *name_label = n;
    while (*n && *n != '.')
      n++;
    const char *pattern_label = p;
    while (*p && *p != '.')
      p++;
    if (!is_string_matching_glob_pattern(
        name_label, (size_t) (n - name_label),
        pattern_label, (size_t) (p - pattern_label)))
      break;
    if (*n)
      n++;
    if (*p)
      p++;
  } while (*n && *p);
  
  return !*n && !*p;
}

#endif
