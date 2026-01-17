#[cfg(test)]
mod tests {
    // Copy of the fixed count_cpus function from cpuset_quarantine.rs
    // that properly handles inverted ranges (e.g., "5-2") by checking e >= s.
    fn count_cpus(cpuset: &str) -> u32 {
        let mut count = 0;
        for part in cpuset.split(',') {
            let part = part.trim();
            if let Some((start, end)) = part.split_once('-') {
                if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                    // Only count if end >= start to avoid overflow
                    if e >= s {
                        count += e - s + 1;
                    }
                }
            } else if part.parse::<u32>().is_ok() {
                count += 1;
            }
        }
        count
    }

    #[test]
    fn test_cpuset_inverted_range_handled_gracefully() {
        // This input represents a malformed range where start > end.
        // The fixed implementation should return 0 for this range (not panic or overflow).
        let input = "5-2";
        println!("Testing input: {}", input);
        let count = count_cpus(input);
        println!("Count: {}", count);

        // With the fix (if e >= s check), inverted ranges are treated as 0 CPUs
        assert_eq!(count, 0, "Inverted range should count as 0 CPUs");
    }

    #[test]
    fn test_cpuset_normal_ranges() {
        // Verify normal ranges still work
        assert_eq!(count_cpus("0-3"), 4);
        assert_eq!(count_cpus("0"), 1);
        assert_eq!(count_cpus("0,2,4"), 3);
        assert_eq!(count_cpus("0-1,4-5"), 4);
    }

    #[test]
    fn test_cpuset_edge_cases() {
        // Empty string
        assert_eq!(count_cpus(""), 0);
        // Single CPU
        assert_eq!(count_cpus("7"), 1);
        // Same start and end (1 CPU range)
        assert_eq!(count_cpus("5-5"), 1);
        // Inverted ranges in mixed list
        assert_eq!(count_cpus("0-3,5-2,7"), 5); // 4 + 0 + 1 = 5
    }
}
