//! DNS question hashing
//!
//! Provides efficient hashing for DNS questions to enable deduplication of
//! concurrent queries. Replaces C implementation from hash-questions.c.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// DNS question for hashing purposes
///
/// Represents the key parts of a DNS query that uniquely identify it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    /// Domain name being queried
    pub name: String,
    
    /// Query type (A, AAAA, MX, etc.)
    pub qtype: u16,
    
    /// Query class (usually IN = 1)
    pub qclass: u16,
}

impl DnsQuestion {
    /// Create a new DNS question
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name (normalized to lowercase)
    /// * `qtype` - Query type
    /// * `qclass` - Query class (typically 1 for IN)
    #[must_use] 
    pub fn new(name: &str, qtype: u16, qclass: u16) -> Self {
        Self {
            name: name.to_lowercase(), // Normalize for case-insensitive matching
            qtype,
            qclass,
        }
    }

    /// Compute hash value for this question
    #[must_use] 
    pub fn hash_value(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

/// DNS question hash table for deduplication
///
/// Tracks pending queries to avoid sending duplicate requests for the same question.
pub struct QuestionHashTable {
    /// Map from question hash to list of pending query IDs
    pending: std::collections::HashMap<u64, Vec<u16>>,
}

impl QuestionHashTable {
    /// Create a new empty hash table
    #[must_use] 
    pub fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
        }
    }

    /// Check if a question is already pending
    ///
    /// # Arguments
    ///
    /// * `question` - DNS question to check
    ///
    /// # Returns
    ///
    /// Returns true if this question already has a pending query.
    #[must_use] 
    pub fn is_pending(&self, question: &DnsQuestion) -> bool {
        let hash = question.hash_value();
        self.pending.contains_key(&hash)
    }

    /// Add a pending query
    ///
    /// # Arguments
    ///
    /// * `question` - DNS question
    /// * `query_id` - Query ID from DNS packet header
    ///
    /// # Returns
    ///
    /// Returns true if this is the first query for this question,
    /// false if there were already pending queries.
    pub fn add_pending(&mut self, question: &DnsQuestion, query_id: u16) -> bool {
        let hash = question.hash_value();
        let entry = self.pending.entry(hash).or_default();
        
        let is_first = entry.is_empty();
        entry.push(query_id);
        is_first
    }

    /// Remove a pending query and get all query IDs for that question
    ///
    /// # Arguments
    ///
    /// * `question` - DNS question
    ///
    /// # Returns
    ///
    /// Returns list of all query IDs that were waiting for this question.
    pub fn remove_pending(&mut self, question: &DnsQuestion) -> Vec<u16> {
        let hash = question.hash_value();
        self.pending.remove(&hash).unwrap_or_default()
    }

    /// Get all pending query IDs for a question
    ///
    /// # Arguments
    ///
    /// * `question` - DNS question
    ///
    /// # Returns
    ///
    /// Returns reference to list of pending query IDs, or None if not pending.
    #[must_use] 
    pub fn get_pending(&self, question: &DnsQuestion) -> Option<&Vec<u16>> {
        let hash = question.hash_value();
        self.pending.get(&hash)
    }

    /// Get the number of unique pending questions
    #[must_use] 
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Check if there are no pending questions
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Clear all pending questions
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Get total number of pending queries (across all questions)
    #[must_use] 
    pub fn total_pending_queries(&self) -> usize {
        self.pending.values().map(std::vec::Vec::len).sum()
    }
}

impl Default for QuestionHashTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_question_basic() {
        let q1 = DnsQuestion::new("example.com", 1, 1);
        let q2 = DnsQuestion::new("example.com", 1, 1);
        
        assert_eq!(q1, q2);
        assert_eq!(q1.hash_value(), q2.hash_value());
    }

    #[test]
    fn test_dns_question_case_insensitive() {
        let q1 = DnsQuestion::new("example.com", 1, 1);
        let q2 = DnsQuestion::new("EXAMPLE.COM", 1, 1);
        
        // Names should be normalized to lowercase
        assert_eq!(q1, q2);
        assert_eq!(q1.hash_value(), q2.hash_value());
    }

    #[test]
    fn test_dns_question_different_types() {
        let q1 = DnsQuestion::new("example.com", 1, 1); // A record
        let q2 = DnsQuestion::new("example.com", 28, 1); // AAAA record
        
        assert_ne!(q1, q2);
        assert_ne!(q1.hash_value(), q2.hash_value());
    }

    #[test]
    fn test_question_hash_table_empty() {
        let table = QuestionHashTable::new();
        
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.total_pending_queries(), 0);
    }

    #[test]
    fn test_question_hash_table_add_pending() {
        let mut table = QuestionHashTable::new();
        let question = DnsQuestion::new("example.com", 1, 1);
        
        assert!(!table.is_pending(&question));
        
        let is_first = table.add_pending(&question, 0x1234);
        assert!(is_first);
        assert!(table.is_pending(&question));
        assert_eq!(table.len(), 1);
        assert_eq!(table.total_pending_queries(), 1);
    }

    #[test]
    fn test_question_hash_table_duplicate_queries() {
        let mut table = QuestionHashTable::new();
        let question = DnsQuestion::new("example.com", 1, 1);
        
        let is_first = table.add_pending(&question, 0x1234);
        assert!(is_first);
        
        let is_first = table.add_pending(&question, 0x5678);
        assert!(!is_first);
        
        assert_eq!(table.len(), 1); // Still one unique question
        assert_eq!(table.total_pending_queries(), 2); // But two queries
        
        let pending = table.get_pending(&question).unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&0x1234));
        assert!(pending.contains(&0x5678));
    }

    #[test]
    fn test_question_hash_table_remove_pending() {
        let mut table = QuestionHashTable::new();
        let question = DnsQuestion::new("example.com", 1, 1);
        
        table.add_pending(&question, 0x1234);
        table.add_pending(&question, 0x5678);
        
        let query_ids = table.remove_pending(&question);
        assert_eq!(query_ids.len(), 2);
        assert!(query_ids.contains(&0x1234));
        assert!(query_ids.contains(&0x5678));
        
        assert!(!table.is_pending(&question));
        assert!(table.is_empty());
    }

    #[test]
    fn test_question_hash_table_multiple_questions() {
        let mut table = QuestionHashTable::new();
        
        let q1 = DnsQuestion::new("example.com", 1, 1);
        let q2 = DnsQuestion::new("example.org", 1, 1);
        
        table.add_pending(&q1, 0x1234);
        table.add_pending(&q2, 0x5678);
        
        assert_eq!(table.len(), 2);
        assert_eq!(table.total_pending_queries(), 2);
        assert!(table.is_pending(&q1));
        assert!(table.is_pending(&q2));
    }

    #[test]
    fn test_question_hash_table_clear() {
        let mut table = QuestionHashTable::new();
        let question = DnsQuestion::new("example.com", 1, 1);
        
        table.add_pending(&question, 0x1234);
        assert!(!table.is_empty());
        
        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }
}
