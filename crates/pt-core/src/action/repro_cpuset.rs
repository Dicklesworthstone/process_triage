#[cfg(all(test, target_os = "linux"))]
mod tests {
    use crate::action::cpuset_quarantine::CpusetQuarantineConfig;

    #[test]
    fn test_cpuset_inverted_range_handled_gracefully() {
        // Exercise the actual production parser. Silently discarding a malformed
        // range can turn a requested quarantine into an inherited CPU set.
        for input in ["5-2", "0-3,5-2,7"] {
            assert!(CpusetQuarantineConfig::with_specific_cpus(input)
                .cpuset_string("0-7")
                .is_err());
        }
    }

    #[test]
    fn test_cpuset_normal_ranges() {
        for input in ["0-3", "0", "0,2,4", "0-1,4-5"] {
            assert_eq!(
                CpusetQuarantineConfig::with_specific_cpus(input)
                    .cpuset_string("0-7")
                    .unwrap(),
                input
            );
        }
    }

    #[test]
    fn test_cpuset_edge_cases() {
        assert!(CpusetQuarantineConfig::with_specific_cpus("")
            .cpuset_string("0-7")
            .is_err());
        assert_eq!(
            CpusetQuarantineConfig::with_specific_cpus("7")
                .cpuset_string("0-7")
                .unwrap(),
            "7"
        );
        assert_eq!(
            CpusetQuarantineConfig::with_specific_cpus("5-5")
                .cpuset_string("0-7")
                .unwrap(),
            "5"
        );
        assert_eq!(
            CpusetQuarantineConfig::with_cpus(2)
                .cpuset_string("4,8,12")
                .unwrap(),
            "4,8"
        );
    }
}
