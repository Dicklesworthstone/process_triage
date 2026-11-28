//! Size of JSON text after the MCP transport escapes it inside ToolContent.

pub(super) fn escaped_len(text: &str) -> usize {
    text.len()
        + text
            .bytes()
            .map(|b| match b {
                b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 8 | 12 => 1,
                0..=31 => 5,
                _ => 0,
            })
            .sum::<usize>()
}

pub(super) fn result_size(text: &str) -> usize {
    // Reserve success-result framing. Client-supplied request IDs are echoed
    // by the transport and can independently have arbitrary length.
    128 + escaped_len(text)
}
