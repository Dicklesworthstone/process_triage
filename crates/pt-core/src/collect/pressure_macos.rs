//! Parsers for read-only native macOS pressure sensors.
//!
//! Apple's `vm_stat` prints the kernel page size and subtracts speculative pages
//! from its displayed free count. Adding the two displayed counts therefore
//! recovers the native free count, without counting inactive or compressed pages
//! as available memory. See:
//! <https://github.com/apple-oss-distributions/system_cmds/blob/main/vm_stat/vm_stat.c>
//! and <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/vm_statistics.h>.
//!
//! Collectors must run `sysctl` with `LC_ALL=C`: its swap formatter honors the
//! numeric locale and prints MiB with two decimal places. The parser validates
//! that rounded presentation without claiming byte-exact swap accounting.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MacosVmStats {
    /// Free plus speculative pages in bytes, matching Mach's `free_count`.
    pub free: u64,
    /// Resident file-backed pages in bytes; not a guarantee of reclaimability.
    pub file_backed: Option<u64>,
    pub anonymous: Option<u64>,
    /// Lifetime native page counts, not bytes or major-fault counts.
    pub swapins: Option<u64>,
    pub swapouts: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MacosSwapUsage {
    /// Bytes reconstructed from `sysctl`'s rounded MiB presentation.
    pub total: u64,
    pub free: u64,
}

fn unsigned(value: &str, source: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{source}: expected an unsigned decimal integer"));
    }
    value
        .parse()
        .map_err(|_| format!("{source}: integer exceeds u64"))
}

/// Parse `sysctl -n hw.memsize`, which Apple defines as physical RAM bytes.
/// <https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_system_capabilities>
pub(crate) fn parse_memsize(text: &str) -> Result<u64, String> {
    let bytes = unsigned(text.trim(), "hw.memsize")?;
    if bytes == 0 {
        return Err("hw.memsize: physical RAM must be positive".to_string());
    }
    Ok(bytes)
}

/// Parse currently enabled logical CPUs, not `hw.logicalcpu_max` capacity.
pub(crate) fn parse_logical_cpus(text: &str) -> Result<u32, String> {
    let cpus = unsigned(text.trim(), "hw.logicalcpu")?;
    u32::try_from(cpus)
        .ok()
        .filter(|cpus| *cpus > 0)
        .ok_or_else(|| "hw.logicalcpu: CPU count must be positive and fit u32".to_string())
}

/// Parse `kern.memorystatus_vm_pressure_level`'s dispatch flags. These are
/// 1=normal, 2=warning, 4=critical, not the kernel's internal 0/1/2/3 enum.
/// `kern.memorystatus_level` is a different measure and is not accepted here.
/// <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_memorystatus_notify.c>
/// <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/event_private.h>
pub(crate) fn parse_pressure_level(text: &str) -> Result<u32, String> {
    match unsigned(text.trim(), "kern.memorystatus_vm_pressure_level")? {
        level @ (1 | 2 | 4) => Ok(level as u32),
        _ => Err("kern.memorystatus_vm_pressure_level: unknown pressure level".to_string()),
    }
}

fn page_bytes(pages: u64, page_size: u64, name: &str) -> Result<u64, String> {
    pages
        .checked_mul(page_size)
        .ok_or_else(|| format!("vm_stat: {name} byte count exceeds u64"))
}

/// Parse the one-shot `vm_stat` output. Known malformed or duplicate fields
/// invalidate the reading; unknown named fields remain forward compatible.
/// The page size is read from the output, supporting both 4 KiB and 16 KiB hosts.
pub(crate) fn parse_vm_stat(text: &str) -> Result<MacosVmStats, String> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let header = lines
        .next()
        .ok_or_else(|| "vm_stat: missing page-size header".to_string())?;
    let page_size = header
        .strip_prefix("Mach Virtual Memory Statistics: (page size of ")
        .and_then(|value| value.strip_suffix(" bytes)"))
        .ok_or_else(|| "vm_stat: invalid page-size header".to_string())?;
    let page_size = unsigned(page_size, "vm_stat page size")?;
    if !page_size.is_power_of_two() {
        return Err("vm_stat: page size must be a positive power of two".to_string());
    }

    let mut seen = BTreeSet::new();
    let (mut free, mut speculative, mut file_backed, mut anonymous) = (None, None, None, None);
    let (mut swapins, mut swapouts) = (None, None);
    for line in lines {
        if line.starts_with("Mach Virtual Memory Statistics:") {
            return Err("vm_stat: duplicate page-size header".to_string());
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "vm_stat: malformed statistics row".to_string())?;
        let name = name.trim();
        if !matches!(
            name,
            "Pages free"
                | "Pages active"
                | "Pages inactive"
                | "Pages speculative"
                | "Pages throttled"
                | "Pages wired down"
                | "Pages purgeable"
                | "\"Translation faults\""
                | "Pages copy-on-write"
                | "Pages zero filled"
                | "Pages reactivated"
                | "Pages purged"
                | "File-backed pages"
                | "Anonymous pages"
                | "Pages stored in compressor"
                | "Pages occupied by compressor"
                | "Decompressions"
                | "Compressions"
                | "Pageins"
                | "Pageouts"
                | "Swapins"
                | "Swapouts"
        ) {
            continue;
        }
        if !seen.insert(name) {
            return Err(format!("vm_stat: duplicate {name} counter"));
        }
        let value = value.trim();
        let count = unsigned(value.strip_suffix('.').unwrap_or(value), name)?;
        match name {
            "Pages free" => free = Some(count),
            "Pages speculative" => speculative = Some(count),
            "File-backed pages" => file_backed = Some(page_bytes(count, page_size, name)?),
            "Anonymous pages" => anonymous = Some(page_bytes(count, page_size, name)?),
            "Swapins" => swapins = Some(count),
            "Swapouts" => swapouts = Some(count),
            _ => {}
        }
    }
    let free = free.ok_or_else(|| "vm_stat: missing Pages free counter".to_string())?;
    let speculative =
        speculative.ok_or_else(|| "vm_stat: missing Pages speculative counter".to_string())?;
    let reusable = free
        .checked_add(speculative)
        .ok_or_else(|| "vm_stat: free plus speculative count exceeds u64".to_string())?;
    Ok(MacosVmStats {
        free: page_bytes(reusable, page_size, "free plus speculative")?,
        file_backed,
        anonymous,
        swapins,
        swapouts,
    })
}

/// Return (hundredths of MiB, nearest bytes), avoiding floating-point loss or
/// saturating casts for oversized values.
fn swap_size(text: &str) -> Result<(u128, u64), String> {
    let value = text
        .strip_suffix('M')
        .ok_or_else(|| "vm.swapusage: expected a MiB value ending in M".to_string())?;
    let (whole, fraction) = value
        .split_once('.')
        .ok_or_else(|| "vm.swapusage: expected two decimal places".to_string())?;
    if fraction.len() != 2 {
        return Err("vm.swapusage: expected two decimal places".to_string());
    }
    let whole = unsigned(whole, "vm.swapusage")?;
    let fraction = unsigned(fraction, "vm.swapusage")?;
    let hundredths = u128::from(whole) * 100 + u128::from(fraction);
    let bytes = (hundredths * 1_048_576 + 50) / 100;
    let bytes =
        u64::try_from(bytes).map_err(|_| "vm.swapusage: byte count exceeds u64".to_string())?;
    Ok((hundredths, bytes))
}

/// Parse `sysctl -n vm.swapusage` (or its named form). Apple's formatter rounds
/// total, used and free independently to 0.01 MiB, so their displayed sum can
/// differ by one rounding unit. Larger mismatches are unavailable, not clamped.
/// <https://github.com/apple-oss-distributions/system_cmds/blob/main/sysctl/sysctl.c>
pub(crate) fn parse_swap_usage(text: &str) -> Result<MacosSwapUsage, String> {
    let text = text.trim();
    let text = text.strip_prefix("vm.swapusage:").unwrap_or(text).trim();
    let fields: Vec<_> = text.split_whitespace().collect();
    if !(fields.len() == 9 || (fields.len() == 10 && fields[9] == "(encrypted)"))
        || fields[0] != "total"
        || fields[1] != "="
        || fields[3] != "used"
        || fields[4] != "="
        || fields[6] != "free"
        || fields[7] != "="
    {
        return Err("vm.swapusage: expected total, used and free fields".to_string());
    }
    let total = swap_size(fields[2])?;
    let used = swap_size(fields[5])?;
    let free = swap_size(fields[8])?;
    if used.0 > total.0 || free.0 > total.0 || total.0.abs_diff(used.0 + free.0) > 1 {
        return Err("vm.swapusage: inconsistent total, used and free values".to_string());
    }
    Ok(MacosSwapUsage {
        total: total.1,
        free: free.1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm_stat(page_size: u64, rows: &str) -> String {
        format!("Mach Virtual Memory Statistics: (page size of {page_size} bytes)\n{rows}")
    }

    #[test]
    fn native_free_adds_printed_speculative_once_on_both_page_sizes() {
        for page_size in [4096, 16384] {
            let stats = parse_vm_stat(&vm_stat(
                page_size,
                "Pages free: 100.\nPages speculative: 20.\nFile-backed pages: 400.\n\
                 Anonymous pages: 300.\nSwapins: 9876543210.\nSwapouts: 12345678901.\n\
                 Pages inactive: 999.\nPages purgeable: 100.\n\
                 Pages stored in compressor: 2000.\nPages occupied by compressor: 1000.\n",
            ))
            .unwrap();
            assert_eq!(stats.free, 120 * page_size);
            assert_eq!(stats.file_backed, Some(400 * page_size));
            assert_eq!(stats.anonymous, Some(300 * page_size));
            assert_eq!(stats.swapins, Some(9876543210));
            assert_eq!(stats.swapouts, Some(12345678901));
        }
    }

    #[test]
    fn missing_optional_fields_remain_unknown_and_observed_zero_is_retained() {
        let stats = parse_vm_stat(&vm_stat(
            4096,
            "Pages free: 0.\nPages speculative: 0.\nSwapins: 0.\n",
        ))
        .unwrap();
        assert_eq!(stats.free, 0);
        assert_eq!(stats.file_backed, None);
        assert_eq!(stats.anonymous, None);
        assert_eq!(stats.swapins, Some(0));
        assert_eq!(stats.swapouts, None);
    }

    #[test]
    fn requires_both_free_counters_and_the_page_size_header() {
        for text in [
            "".to_string(),
            "Pages free: 1.\nPages speculative: 2.\n".to_string(),
            vm_stat(4096, "Pages free: 1.\n"),
            vm_stat(4096, "Pages speculative: 2.\n"),
        ] {
            assert!(parse_vm_stat(&text).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_duplicate_known_rows_and_headers() {
        for extra in [
            "Pages free: 2.\n",
            "Pages speculative: 2.\n",
            "Swapins: 1.\nSwapins: 1.\n",
            "Pages inactive: 1.\nPages inactive: 1.\n",
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n",
        ] {
            let text = vm_stat(
                4096,
                &format!("Pages free: 1.\nPages speculative: 1.\n{extra}"),
            );
            assert!(parse_vm_stat(&text).is_err(), "{extra}");
        }
    }

    #[test]
    fn rejects_malformed_known_rows_without_discarding_the_error() {
        for value in ["-1.", "+1.", "1.5.", "1..", "1K", "NaN", "", "1. extra"] {
            let text = vm_stat(
                4096,
                &format!("Pages free: 1.\nPages speculative: 1.\nAnonymous pages: {value}\n"),
            );
            assert!(parse_vm_stat(&text).is_err(), "{value}");
        }
        assert!(parse_vm_stat(&vm_stat(
            4096,
            "Pages free: 1.\nPages speculative: 1.\ntruncated row"
        ))
        .is_err());
    }

    #[test]
    fn rejects_invalid_page_sizes_and_overflowing_counts() {
        for page_size in [0, 3, 4097] {
            assert!(parse_vm_stat(&vm_stat(
                page_size,
                "Pages free: 1.\nPages speculative: 1.\n"
            ))
            .is_err());
        }
        for rows in [
            format!("Pages free: {}.\nPages speculative: 1.\n", u64::MAX),
            format!("Pages free: {}.\nPages speculative: 0.\n", u64::MAX),
            format!(
                "Pages free: 1.\nPages speculative: 0.\nFile-backed pages: {}.\n",
                u64::MAX
            ),
            "Pages free: 18446744073709551616.\nPages speculative: 0.\n".to_string(),
        ] {
            assert!(parse_vm_stat(&vm_stat(4096, &rows)).is_err(), "{rows}");
        }
    }

    #[test]
    fn tolerates_whitespace_and_new_named_vm_fields() {
        let text = "\n Mach Virtual Memory Statistics: (page size of 4096 bytes) \n\
                    Pages free:  10. \nPages speculative:  2.\n\
                    Future statistic: a future representation\n";
        assert_eq!(parse_vm_stat(text).unwrap().free, 12 * 4096);
    }

    #[test]
    fn validates_memsize_and_cpu_counts_without_silent_defaults() {
        assert_eq!(parse_memsize("17179869184\n").unwrap(), 17_179_869_184);
        assert_eq!(parse_logical_cpus("12\n").unwrap(), 12);
        for value in ["", "0", "-1", "+1", "1.0", "1 2", "18446744073709551616"] {
            assert!(parse_memsize(value).is_err(), "{value}");
            assert!(parse_logical_cpus(value).is_err(), "{value}");
        }
        assert!(parse_logical_cpus("4294967296").is_err());
    }

    #[test]
    fn accepts_only_native_dispatch_pressure_levels() {
        for level in [1, 2, 4] {
            assert_eq!(parse_pressure_level(&format!("{level}\n")).unwrap(), level);
        }
        for level in ["0", "3", "5", "6", "7", "8", "-1", "normal", "1 2", "+1"] {
            assert!(parse_pressure_level(level).is_err(), "{level}");
        }
    }

    #[test]
    fn parses_named_and_unnamed_swap_usage_in_binary_mebibytes() {
        for text in [
            "total = 4096.00M  used = 1024.25M  free = 3071.75M  (encrypted)",
            "vm.swapusage: total = 4096.00M used = 1024.25M free = 3071.75M\n",
        ] {
            let swap = parse_swap_usage(text).unwrap();
            assert_eq!(swap.total, 4_294_967_296);
            assert_eq!(swap.free, 3_220_963_328);
        }
        assert_eq!(
            parse_swap_usage("total = 0.00M used = 0.00M free = 0.00M").unwrap(),
            MacosSwapUsage { total: 0, free: 0 }
        );
    }

    #[test]
    fn allows_only_the_single_rounding_unit_from_independent_two_decimal_values() {
        for text in [
            "total = 1.00M used = 0.33M free = 0.66M",
            "total = 1.00M used = 0.34M free = 0.67M",
        ] {
            assert!(parse_swap_usage(text).is_ok(), "{text}");
        }
        for text in [
            "total = 1.00M used = 0.33M free = 0.65M",
            "total = 1.00M used = 0.35M free = 0.67M",
            "total = 1.00M used = 1.01M free = 0.00M",
            "total = 1.00M used = 0.00M free = 1.01M",
            "total = 100.00M used = 1.00M free = 1.00M",
        ] {
            assert!(parse_swap_usage(text).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_partial_localized_nonfinite_or_ambiguous_swap_output() {
        for text in [
            "",
            "total = 1.00M used = 0.00M",
            "total = 1,00M used = 0,00M free = 1,00M",
            "total = NaNM used = 0.00M free = NaNM",
            "total = infM used = 0.00M free = infM",
            "total = -1.00M used = 0.00M free = -1.00M",
            "total = +1.00M used = 0.00M free = 1.00M",
            "total = 1.0M used = 0.0M free = 1.0M",
            "total = 1.00G used = 0.00G free = 1.00G",
            "total = 1.00M used = 0.00M free = 1.00M total = 1.00M",
            "total = 1.00M used = 0.00M free = 1.00M unexpected",
            "total = 18446744073709551615.00M used = 0.00M free = 18446744073709551615.00M",
        ] {
            assert!(parse_swap_usage(text).is_err(), "{text}");
        }
    }
}
