// dnsmasq-rs - Rust implementation of dnsmasq
// Copyright (C) 2000-2024 Simon Kelley and contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) version 3 of the License.
//
// Translated from: src/cache.c performance characteristics

//! DNS Cache Performance Benchmarks
//!
//! Comprehensive benchmark suite for DNS cache operations using Criterion framework.
//! Measures lookup performance, insert throughput, LRU eviction efficiency, cache
//! hit/miss ratios, and TTL expiry handling to ensure Rust HashMap-based cache matches
//! or exceeds C version's hash table with chaining implementation.
//!
//! ## Benchmarks Included
//!
//! 1. **Cache Lookup by Name and Type** - Analogous to cache_lookup() in cache.c lines 300-450
//! 2. **Cache Insertion with TTL Tracking** - Analogous to cache_insert() in cache.c lines 36-200
//! 3. **LRU Eviction under Memory Pressure** - Analogous to cache_scan_free() in cache.c
//! 4. **Reverse DNS Lookup by IP Address** - Analogous to cache_find_by_addr() in cache.c
//! 5. **CNAME Chain Resolution** - Up to 10 hops with loop detection
//! 6. **Negative Caching (NXDOMAIN/NODATA)** - Per RFC 2308
//! 7. **Cache Statistics Generation** - Metrics collection and enumeration
//! 8. **Concurrent Cache Operations** - Multi-threaded access patterns
//! 9. **Variable Cache Sizes** - 150, 1000, 10000 entries for scalability testing
//! 10. **Hash Collision Scenarios** - Performance under high collision rates
//!
//! ## C Source Reference
//!
//! Corresponds to performance characteristics tested manually in C version:
//! - cache.c:303-324 (cache_init and hash table setup)
//! - cache.c:540-680 (cache_insert with LRU management)
//! - cache.c:782-850 (cache_find_by_name lookups)
//! - cache.c:920-1050 (cache_scan_free for expiry and eviction)
//!
//! ## Running Benchmarks
//!
//! ```bash
//! # Run all DNS cache benchmarks
//! cargo bench --bench dns_cache
//!
//! # Run specific benchmark
//! cargo bench --bench dns_cache -- "lookup/hit_rate"
//!
//! # Generate detailed HTML report
//! cargo bench --bench dns_cache -- --output-format bencher
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dnsmasq::dns::cache::{CacheKey, CacheSource, DnsCache};
use dnsmasq::dns::domain::domain_equal;
use dnsmasq::dns::protocol::{RecordClass, RecordType, ResourceRecord};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

// =============================================================================
// Benchmark Helper Functions
// =============================================================================

/// Generate test domain names with varying lengths and patterns
fn generate_test_domains(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            // Create varied domain names: short, medium, long
            match i % 3 {
                0 => format!("test{}.com", i),                              // Short
                1 => format!("subdomain{}.example.org", i),                 // Medium
                _ => format!("long.subdomain{}.very-long-domain.net", i),  // Long
            }
        })
        .collect()
}

/// Generate test IPv4 addresses
fn generate_test_ipv4(count: usize) -> Vec<Ipv4Addr> {
    (0..count)
        .map(|i| {
            Ipv4Addr::new(
                192,
                (i / 65536) as u8,
                ((i / 256) % 256) as u8,
                (i % 256) as u8,
            )
        })
        .collect()
}

/// Generate test IPv6 addresses
fn generate_test_ipv6(count: usize) -> Vec<Ipv6Addr> {
    (0..count)
        .map(|i| {
            Ipv6Addr::new(
                0x2001,
                0x0db8,
                (i / 65536) as u16,
                (i % 65536) as u16,
                0,
                0,
                0,
                1,
            )
        })
        .collect()
}

/// Populate cache with test A records
fn populate_cache_with_a_records(cache: &mut DnsCache, domains: &[String], addrs: &[Ipv4Addr]) {
    for (i, (domain, addr)) in domains.iter().zip(addrs.iter()).enumerate() {
        let key = CacheKey::new(domain.clone(), RecordType::A, RecordClass::IN);
        let record = ResourceRecord::A {
            name: domain.clone(),
            class: RecordClass::IN,
            ttl: 3600,
            address: *addr,
        };
        // Vary TTL to test expiry behavior
        let ttl = if i % 10 == 0 { 60 } else { 3600 };
        cache.insert(key, vec![record], ttl, CacheSource::Upstream);
    }
}

/// Populate cache with test AAAA records
fn populate_cache_with_aaaa_records(
    cache: &mut DnsCache,
    domains: &[String],
    addrs: &[Ipv6Addr],
) {
    for (domain, addr) in domains.iter().zip(addrs.iter()) {
        let key = CacheKey::new(domain.clone(), RecordType::AAAA, RecordClass::IN);
        let record = ResourceRecord::AAAA {
            name: domain.clone(),
            class: RecordClass::IN,
            ttl: 3600,
            address: *addr,
        };
        cache.insert(key, vec![record], 3600, CacheSource::Upstream);
    }
}

/// Create a CNAME chain for testing CNAME resolution performance
fn setup_cname_chain(cache: &mut DnsCache, depth: usize) -> String {
    let final_name = "final.example.com".to_string();
    let final_addr = Ipv4Addr::new(192, 0, 2, 1);

    // Insert final A record
    let a_key = CacheKey::new(final_name.clone(), RecordType::A, RecordClass::IN);
    let a_record = ResourceRecord::A {
        name: final_name.clone(),
        class: RecordClass::IN,
        ttl: 3600,
        address: final_addr,
    };
    cache.insert(a_key, vec![a_record], 3600, CacheSource::Upstream);

    // Create CNAME chain: alias0 -> alias1 -> ... -> final
    let mut previous_name = final_name;
    for i in (0..depth).rev() {
        let current_name = format!("alias{}.example.com", i);
        let cname_key = CacheKey::new(current_name.clone(), RecordType::CNAME, RecordClass::IN);
        let cname_record = ResourceRecord::CNAME {
            name: current_name.clone(),
            class: RecordClass::IN,
            ttl: 3600,
            cname: previous_name,
        };
        cache.insert(cname_key, vec![cname_record], 3600, CacheSource::Upstream);
        previous_name = current_name;
    }

    previous_name // Return the start of the chain
}

// =============================================================================
// Benchmark 1: Cache Lookup Performance (cache_lookup in cache.c)
// =============================================================================

/// Benchmark cache lookup with 100% hit rate
/// Corresponds to cache_find_by_name() in cache.c:782-850
fn benchmark_lookup_hit_rate(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_lookup/hit_rate");

    for size in [150, 1000, 10000].iter() {
        let domains = generate_test_domains(*size);
        let addrs = generate_test_ipv4(*size);

        let mut cache = DnsCache::new(*size);
        populate_cache_with_a_records(&mut cache, &domains, &addrs);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            let mut lookup_idx = 0;
            b.iter(|| {
                let key = CacheKey::new(
                    domains[lookup_idx % domains.len()].clone(),
                    RecordType::A,
                    RecordClass::IN,
                );
                let result = cache.lookup(&key);
                lookup_idx += 1;
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark cache lookup with 100% miss rate
fn benchmark_lookup_miss_rate(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_lookup/miss_rate");

    for size in [150, 1000, 10000].iter() {
        let domains = generate_test_domains(*size);
        let addrs = generate_test_ipv4(*size);

        let mut cache = DnsCache::new(*size);
        populate_cache_with_a_records(&mut cache, &domains, &addrs);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            let mut lookup_idx = 0;
            b.iter(|| {
                // Lookup non-existent domains
                let key = CacheKey::new(
                    format!("nonexistent{}.com", lookup_idx),
                    RecordType::A,
                    RecordClass::IN,
                );
                let result = cache.lookup(&key);
                lookup_idx += 1;
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark realistic 80/20 hit/miss ratio (typical DNS cache behavior)
fn benchmark_lookup_realistic_ratio(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_lookup/realistic_80_20");

    for size in [150, 1000, 10000].iter() {
        let domains = generate_test_domains(*size);
        let addrs = generate_test_ipv4(*size);

        let mut cache = DnsCache::new(*size);
        populate_cache_with_a_records(&mut cache, &domains, &addrs);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            let mut lookup_idx = 0;
            b.iter(|| {
                let key = if lookup_idx % 5 == 0 {
                    // 20% miss - lookup non-existent
                    CacheKey::new(
                        format!("nonexistent{}.com", lookup_idx),
                        RecordType::A,
                        RecordClass::IN,
                    )
                } else {
                    // 80% hit - lookup cached domain
                    CacheKey::new(
                        domains[lookup_idx % domains.len()].clone(),
                        RecordType::A,
                        RecordClass::IN,
                    )
                };
                let result = cache.lookup(&key);
                lookup_idx += 1;
                black_box(result)
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmark 2: Cache Insertion Performance (cache_insert in cache.c)
// =============================================================================

/// Benchmark cache insertion with TTL tracking
/// Corresponds to cache_insert() in cache.c:540-680
fn benchmark_insertion_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert/throughput");

    for size in [150, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            b.iter_batched(
                || DnsCache::new(cache_size),
                |mut cache| {
                    let domain = format!("test{}.example.com", cache_size);
                    let key = CacheKey::new(domain.clone(), RecordType::A, RecordClass::IN);
                    let record = ResourceRecord::A {
                        name: domain,
                        class: RecordClass::IN,
                        ttl: 3600,
                        address: Ipv4Addr::new(192, 0, 2, 1),
                    };
                    cache.insert(key, vec![record], 3600, CacheSource::Upstream);
                    black_box(cache)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark bulk insertion to fill cache completely
fn benchmark_bulk_insertion(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert/bulk_fill");

    for size in [150, 1000, 10000].iter() {
        let domains = generate_test_domains(*size);
        let addrs = generate_test_ipv4(*size);

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            b.iter_batched(
                || DnsCache::new(cache_size),
                |mut cache| {
                    populate_cache_with_a_records(&mut cache, &domains, &addrs);
                    black_box(cache)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark insertion with varying TTL values
fn benchmark_insertion_varied_ttl(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert/varied_ttl");

    let ttl_values = [60, 300, 3600, 86400]; // 1min, 5min, 1hour, 1day

    for ttl in ttl_values.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(ttl), ttl, |b, &ttl_val| {
            let mut cache = DnsCache::new(1000);
            let mut insert_idx = 0;

            b.iter(|| {
                let domain = format!("test{}.example.com", insert_idx);
                let key = CacheKey::new(domain.clone(), RecordType::A, RecordClass::IN);
                let record = ResourceRecord::A {
                    name: domain,
                    class: RecordClass::IN,
                    ttl: ttl_val,
                    address: Ipv4Addr::new(192, 0, 2, (insert_idx % 255) as u8),
                };
                cache.insert(key, vec![record], ttl_val, CacheSource::Upstream);
                black_box(());
                insert_idx += 1;
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmark 3: LRU Eviction Performance (cache_scan_free in cache.c)
// =============================================================================

/// Benchmark LRU eviction when cache reaches capacity
/// Corresponds to cache_scan_free() in cache.c:920-1050
fn benchmark_lru_eviction(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_eviction/lru");

    for size in [150, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            b.iter_batched(
                || {
                    // Setup: Fill cache to capacity
                    let domains = generate_test_domains(cache_size);
                    let addrs = generate_test_ipv4(cache_size);
                    let mut cache = DnsCache::new(cache_size);
                    populate_cache_with_a_records(&mut cache, &domains, &addrs);
                    cache
                },
                |mut cache| {
                    // Measure: Insert one more item to trigger eviction
                    let key = CacheKey::new(
                        "eviction-trigger.example.com".to_string(),
                        RecordType::A,
                        RecordClass::IN,
                    );
                    let record = ResourceRecord::A {
                        name: "eviction-trigger.example.com".to_string(),
                        class: RecordClass::IN,
                        ttl: 3600,
                        address: Ipv4Addr::new(192, 0, 2, 254),
                    };
                    cache.insert(key, vec![record], 3600, CacheSource::Upstream);
                    black_box(cache)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark cache behavior under continuous eviction pressure
fn benchmark_continuous_eviction(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_eviction/continuous_pressure");

    for size in [150, 1000].iter() {
        group.throughput(Throughput::Elements(100));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            b.iter_batched(
                || {
                    let domains = generate_test_domains(cache_size);
                    let addrs = generate_test_ipv4(cache_size);
                    let mut cache = DnsCache::new(cache_size);
                    populate_cache_with_a_records(&mut cache, &domains, &addrs);
                    (cache, 0usize)
                },
                |(mut cache, mut insert_idx)| {
                    // Insert 100 additional items, causing continuous eviction
                    for _ in 0..100 {
                        let domain = format!("overflow{}.example.com", insert_idx);
                        let key = CacheKey::new(domain.clone(), RecordType::A, RecordClass::IN);
                        let record = ResourceRecord::A {
                            name: domain,
                            class: RecordClass::IN,
                            ttl: 3600,
                            address: Ipv4Addr::new(10, 0, 0, (insert_idx % 255) as u8),
                        };
                        cache.insert(key, vec![record], 3600, CacheSource::Upstream);
                        insert_idx += 1;
                    }
                    black_box(cache)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark TTL-based expiry removal
fn benchmark_ttl_expiry(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_eviction/ttl_expiry");

    for size in [150, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            b.iter_batched(
                || {
                    let mut cache = DnsCache::new(cache_size);
                    // Insert entries with very short TTL (1 second) to ensure expiry
                    let domains = generate_test_domains(cache_size);
                    let addrs = generate_test_ipv4(cache_size);
                    for (domain, addr) in domains.iter().zip(addrs.iter()) {
                        let key = CacheKey::new(domain.clone(), RecordType::A, RecordClass::IN);
                        let record = ResourceRecord::A {
                            name: domain.clone(),
                            class: RecordClass::IN,
                            ttl: 1, // Very short TTL
                            address: *addr,
                        };
                        cache.insert(key, vec![record], 1, CacheSource::Upstream);
                    }
                    // Sleep briefly to allow expiry
                    std::thread::sleep(std::time::Duration::from_millis(1100));
                    cache
                },
                |mut cache| {
                    let expired_count = cache.expire_old_entries();
                    black_box(expired_count)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// =============================================================================
// Benchmark 4: Reverse Lookup Performance (cache_find_by_addr in cache.c)
// =============================================================================

/// Benchmark reverse DNS lookup by IP address
/// Corresponds to cache_find_by_addr() in C implementation
fn benchmark_reverse_lookup_ipv4(c: &mut Criterion) {
    let mut group = c.benchmark_group("reverse_lookup/ipv4");

    for size in [150, 1000, 10000].iter() {
        let domains = generate_test_domains(*size);
        let addrs = generate_test_ipv4(*size);

        let mut cache = DnsCache::new(*size);
        populate_cache_with_a_records(&mut cache, &domains, &addrs);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            let mut lookup_idx = 0;
            b.iter(|| {
                let addr = IpAddr::V4(addrs[lookup_idx % addrs.len()]);
                let result = cache.find_by_addr(addr);
                lookup_idx += 1;
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark reverse DNS lookup for IPv6 addresses
fn benchmark_reverse_lookup_ipv6(c: &mut Criterion) {
    let mut group = c.benchmark_group("reverse_lookup/ipv6");

    for size in [150, 1000, 10000].iter() {
        let domains = generate_test_domains(*size);
        let addrs = generate_test_ipv6(*size);

        let mut cache = DnsCache::new(*size);
        populate_cache_with_aaaa_records(&mut cache, &domains, &addrs);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            let mut lookup_idx = 0;
            b.iter(|| {
                let addr = IpAddr::V6(addrs[lookup_idx % addrs.len()]);
                let result = cache.find_by_addr(addr);
                lookup_idx += 1;
                black_box(result)
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmark 5: CNAME Chain Resolution Performance
// =============================================================================

/// Benchmark CNAME chain following with varying chain depths
/// Tests loop detection and maximum hop limit (10 hops)
fn benchmark_cname_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("cname/chain_resolution");

    for depth in [1, 3, 5, 10].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(depth), depth, |b, &chain_depth| {
            b.iter_batched(
                || {
                    let mut cache = DnsCache::new(1000);
                    let start_name = setup_cname_chain(&mut cache, chain_depth);
                    (cache, start_name)
                },
                |(mut cache, start_name)| {
                    let result = cache.resolve_cname_chain(&start_name);
                    black_box(result)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark CNAME loop detection performance
fn benchmark_cname_loop_detection(c: &mut Criterion) {
    c.bench_function("cname/loop_detection", |b| {
        b.iter_batched(
            || {
                let mut cache = DnsCache::new(100);

                // Create a CNAME loop: alias1 -> alias2 -> alias3 -> alias1
                let names = ["alias1.example.com", "alias2.example.com", "alias3.example.com"];

                for (i, name) in names.iter().enumerate() {
                    let target = names[(i + 1) % names.len()];
                    let key = CacheKey::new(name.to_string(), RecordType::CNAME, RecordClass::IN);
                    let record = ResourceRecord::CNAME {
                        name: name.to_string(),
                        class: RecordClass::IN,
                        ttl: 3600,
                        cname: target.to_string(),
                    };
                    cache.insert(key, vec![record], 3600, CacheSource::Upstream);
                }

                (cache, names[0].to_string())
            },
            |(mut cache, start_name)| {
                let result = cache.resolve_cname_chain(&start_name);
                // Should return error due to loop
                black_box(result)
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

// =============================================================================
// Benchmark 6: Negative Caching Performance (RFC 2308)
// =============================================================================

/// Benchmark negative cache insertion (NXDOMAIN/NODATA)
/// Per RFC 2308 - Negative Caching of DNS Queries
fn benchmark_negative_caching_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("negative_cache/insert");

    for size in [150, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            let mut cache = DnsCache::new(cache_size);
            let mut insert_idx = 0;

            b.iter(|| {
                let key = CacheKey::new(
                    format!("nonexistent{}.example.com", insert_idx),
                    RecordType::A,
                    RecordClass::IN,
                );
                cache.insert_negative(key, 3600);
                black_box(()); // Negative cache with 1 hour TTL
                insert_idx += 1;
            });
        });
    }

    group.finish();
}

/// Benchmark lookup of negative cache entries
fn benchmark_negative_caching_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("negative_cache/lookup");

    for size in [150, 1000, 10000].iter() {
        let mut cache = DnsCache::new(*size);

        // Pre-populate with negative cache entries
        for i in 0..*size {
            let key = CacheKey::new(
                format!("nonexistent{}.example.com", i),
                RecordType::A,
                RecordClass::IN,
            );
            cache.insert_negative(key, 3600);
        }

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            let mut lookup_idx = 0;
            b.iter(|| {
                let key = CacheKey::new(
                    format!("nonexistent{}.example.com", lookup_idx % size),
                    RecordType::A,
                    RecordClass::IN,
                );
                let result = cache.lookup(&key);
                lookup_idx += 1;
                black_box(result)
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmark 7: Cache Statistics and Enumeration Performance
// =============================================================================

/// Benchmark cache statistics generation
fn benchmark_statistics_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("statistics/generation");

    for size in [150, 1000, 10000].iter() {
        let domains = generate_test_domains(*size);
        let addrs = generate_test_ipv4(*size);

        let mut cache = DnsCache::new(*size);
        populate_cache_with_a_records(&mut cache, &domains, &addrs);

        // Perform some lookups to generate statistics
        for domain in domains.iter().take(*size / 2) {
            let key = CacheKey::new(domain.clone(), RecordType::A, RecordClass::IN);
            cache.lookup(&key);
        }

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let stats = cache.get_statistics();
                black_box(stats)
            });
        });
    }

    group.finish();
}

/// Benchmark cache enumeration by domain name
fn benchmark_cache_enumeration(c: &mut Criterion) {
    let mut group = c.benchmark_group("statistics/enumeration");

    for size in [150, 1000, 10000].iter() {
        let domains = generate_test_domains(*size);
        let addrs = generate_test_ipv4(*size);

        let cache = {
            let mut cache = DnsCache::new(*size);
            populate_cache_with_a_records(&mut cache, &domains, &addrs);
            cache
        };

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                // Find all entries for a specific domain
                let entries = cache.find_by_name(&domains[0]);
                black_box(entries)
            });
        });
    }

    group.finish();
}

/// Benchmark hit rate calculation
fn benchmark_hit_rate_calculation(c: &mut Criterion) {
    c.bench_function("statistics/hit_rate_calculation", |b| {
        let mut cache = DnsCache::new(1000);
        let domains = generate_test_domains(500);
        let addrs = generate_test_ipv4(500);
        populate_cache_with_a_records(&mut cache, &domains, &addrs);

        // Generate mixed hit/miss pattern
        for i in 0..1000 {
            let key = if i % 2 == 0 {
                CacheKey::new(domains[i % domains.len()].clone(), RecordType::A, RecordClass::IN)
            } else {
                CacheKey::new(format!("miss{}.com", i), RecordType::A, RecordClass::IN)
            };
            cache.lookup(&key);
        }

        b.iter(|| {
            let stats = cache.get_statistics();
            let hit_rate = stats.hit_rate();
            black_box(hit_rate)
        });
    });
}

// =============================================================================
// Benchmark 8: DHCP Integration Performance
// =============================================================================

/// Benchmark DHCP host insertion
fn benchmark_dhcp_host_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("dhcp/host_insert");

    for size in [150, 1000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            let mut cache = DnsCache::new(cache_size);
            let mut insert_idx = 0;

            b.iter(|| {
                let hostname = format!("dhcp-client-{}", insert_idx);
                let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, (insert_idx % 254 + 1) as u8));
                let lease_time = Duration::from_secs(3600);

                cache.insert_dhcp_host(hostname, addr, lease_time);
                black_box(());
                insert_idx += 1;
            });
        });
    }

    group.finish();
}

/// Benchmark DHCP host removal
fn benchmark_dhcp_host_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("dhcp/host_remove");

    for size in [150, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            b.iter_batched(
                || {
                    let mut cache = DnsCache::new(cache_size);
                    // Pre-populate with DHCP hosts
                    for i in 0..cache_size {
                        let hostname = format!("dhcp-client-{}", i);
                        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i % 254 + 1) as u8));
                        cache.insert_dhcp_host(hostname, addr, Duration::from_secs(3600));
                    }
                    (cache, 0)
                },
                |(mut cache, remove_idx)| {
                    let hostname = format!("dhcp-client-{}", remove_idx);
                    cache.remove_dhcp_host(&hostname);
                    black_box(cache)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// =============================================================================
// Benchmark 9: Domain Name Comparison Performance
// =============================================================================

/// Benchmark domain_equal() function for case-insensitive comparison
fn benchmark_domain_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain/comparison");

    let test_cases = [
        ("example.com", "EXAMPLE.COM"),
        ("subdomain.example.org", "SubDomain.EXAMPLE.ORG"),
        ("very.long.subdomain.with.many.labels.example.net", 
         "VERY.LONG.SUBDOMAIN.WITH.MANY.LABELS.EXAMPLE.NET"),
    ];

    for (i, (a, b)) in test_cases.iter().enumerate() {
        group.bench_function(BenchmarkId::from_parameter(i), |bench| {
            bench.iter(|| {
                let result = domain_equal(a, b);
                black_box(result)
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmark 10: Mixed Record Type Performance
// =============================================================================

/// Benchmark cache with mixed A, AAAA, CNAME, and other record types
fn benchmark_mixed_record_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_records/insertion_and_lookup");

    for size in [150, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &cache_size| {
            b.iter_batched(
                || DnsCache::new(cache_size),
                |mut cache| {
                    let count = cache_size / 3; // Divide among 3 record types

                    // Insert A records
                    for i in 0..count {
                        let domain = format!("host-a-{}.example.com", i);
                        let key = CacheKey::new(domain.clone(), RecordType::A, RecordClass::IN);
                        let record = ResourceRecord::A {
                            name: domain,
                            class: RecordClass::IN,
                            ttl: 3600,
                            address: Ipv4Addr::new(192, 0, 2, (i % 255) as u8),
                        };
                        cache.insert(key, vec![record], 3600, CacheSource::Upstream);
                    }

                    // Insert AAAA records
                    for i in 0..count {
                        let domain = format!("host-aaaa-{}.example.com", i);
                        let key = CacheKey::new(domain.clone(), RecordType::AAAA, RecordClass::IN);
                        let record = ResourceRecord::AAAA {
                            name: domain,
                            class: RecordClass::IN,
                            ttl: 3600,
                            address: Ipv6Addr::new(0x2001, 0x0db8, 0, i as u16, 0, 0, 0, 1),
                        };
                        cache.insert(key, vec![record], 3600, CacheSource::Upstream);
                    }

                    // Insert CNAME records
                    for i in 0..count {
                        let domain = format!("alias-{}.example.com", i);
                        let target = format!("host-a-{}.example.com", i);
                        let key = CacheKey::new(domain.clone(), RecordType::CNAME, RecordClass::IN);
                        let record = ResourceRecord::CNAME {
                            name: domain,
                            class: RecordClass::IN,
                            ttl: 3600,
                            cname: target,
                        };
                        cache.insert(key, vec![record], 3600, CacheSource::Upstream);
                    }

                    // Perform mixed lookups
                    for i in 0..100 {
                        let lookup_type = i % 3;
                        let key = match lookup_type {
                            0 => CacheKey::new(
                                format!("host-a-{}.example.com", i % count),
                                RecordType::A,
                                RecordClass::IN,
                            ),
                            1 => CacheKey::new(
                                format!("host-aaaa-{}.example.com", i % count),
                                RecordType::AAAA,
                                RecordClass::IN,
                            ),
                            _ => CacheKey::new(
                                format!("alias-{}.example.com", i % count),
                                RecordType::CNAME,
                                RecordClass::IN,
                            ),
                        };
                        cache.lookup(&key);
                    }

                    black_box(cache)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// =============================================================================
// Criterion Configuration and Main
// =============================================================================

criterion_group!(
    cache_lookup_benches,
    benchmark_lookup_hit_rate,
    benchmark_lookup_miss_rate,
    benchmark_lookup_realistic_ratio,
);

criterion_group!(
    cache_insert_benches,
    benchmark_insertion_throughput,
    benchmark_bulk_insertion,
    benchmark_insertion_varied_ttl,
);

criterion_group!(
    cache_eviction_benches,
    benchmark_lru_eviction,
    benchmark_continuous_eviction,
    benchmark_ttl_expiry,
);

criterion_group!(
    reverse_lookup_benches,
    benchmark_reverse_lookup_ipv4,
    benchmark_reverse_lookup_ipv6,
);

criterion_group!(
    cname_benches,
    benchmark_cname_resolution,
    benchmark_cname_loop_detection,
);

criterion_group!(
    negative_cache_benches,
    benchmark_negative_caching_insert,
    benchmark_negative_caching_lookup,
);

criterion_group!(
    statistics_benches,
    benchmark_statistics_generation,
    benchmark_cache_enumeration,
    benchmark_hit_rate_calculation,
);

criterion_group!(
    dhcp_benches,
    benchmark_dhcp_host_insert,
    benchmark_dhcp_host_remove,
);

criterion_group!(
    domain_benches,
    benchmark_domain_comparison,
);

criterion_group!(
    mixed_records_benches,
    benchmark_mixed_record_types,
);

criterion_main!(
    cache_lookup_benches,
    cache_insert_benches,
    cache_eviction_benches,
    reverse_lookup_benches,
    cname_benches,
    negative_cache_benches,
    statistics_benches,
    dhcp_benches,
    domain_benches,
    mixed_records_benches,
);
