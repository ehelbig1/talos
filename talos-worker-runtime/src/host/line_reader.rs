//! Byte-level `\n`-delimited line reader for streamed HTTP bodies (SSE).
//!
//! Shared by the guest SSE reader (`http_stream`) and the LLM stream reader
//! (`llm_streaming`). Two defects it replaces, both from decoding each network
//! chunk on its own and re-slicing a `String`:
//!
//! * a multi-byte UTF-8 character split across two chunks was decoded as two
//!   U+FFFD replacement characters — bytes are buffered and a line is decoded
//!   only once it is COMPLETE;
//! * `buffer = buffer[nl + 1..].to_string()` per line copied the whole
//!   remaining buffer for every newline, so a chunk of N newlines cost O(N^2).
//!   Here every byte is scanned once and compaction is amortised.
//!
//! The unterminated tail is capped: a peer streaming a long line with no `\n`
//! gets [`LineTooLong`] rather than growing the buffer without bound.

/// The unterminated line exceeded the reader's cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LineTooLong {
    pub(crate) tail_bytes: usize,
}

pub(crate) struct LineReader {
    buf: Vec<u8>,
    /// Bytes before `pos` have been returned as lines.
    pos: usize,
    /// No `\n` exists in `buf[pos..scan]`; the next search starts here.
    scan: usize,
    /// Start of the current unterminated line (just after the last `\n`).
    tail_start: usize,
    max_line_bytes: usize,
}

impl LineReader {
    pub(crate) fn new(max_line_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            scan: 0,
            tail_start: 0,
            max_line_bytes,
        }
    }

    /// Append a chunk. Fails when the unterminated line exceeds the cap.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), LineTooLong> {
        // Amortised compaction: only move bytes once at least half the buffer
        // is consumed, so the total copy cost stays linear in the input.
        if self.pos > 0 && self.pos * 2 >= self.buf.len() {
            self.buf.drain(..self.pos);
            self.scan -= self.pos;
            self.tail_start -= self.pos;
            self.pos = 0;
        }
        let old_len = self.buf.len();
        self.buf.extend_from_slice(chunk);
        if let Some(i) = chunk.iter().rposition(|&b| b == b'\n') {
            self.tail_start = old_len + i + 1;
        }
        let tail_bytes = self.buf.len() - self.tail_start;
        if tail_bytes > self.max_line_bytes {
            return Err(LineTooLong { tail_bytes });
        }
        Ok(())
    }

    /// Next complete line, without its `\n` (and one trailing `\r`), decoded
    /// as UTF-8 with replacement only for genuinely invalid bytes.
    pub(crate) fn next_line(&mut self) -> Option<String> {
        match self.buf[self.scan..].iter().position(|&b| b == b'\n') {
            Some(off) => {
                let nl = self.scan + off;
                let mut line = &self.buf[self.pos..nl];
                if let [rest @ .., b'\r'] = line {
                    line = rest;
                }
                let out = String::from_utf8_lossy(line).into_owned();
                self.pos = nl + 1;
                self.scan = self.pos;
                Some(out)
            }
            None => {
                self.scan = self.buf.len();
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(r: &mut LineReader) -> Vec<String> {
        std::iter::from_fn(|| r.next_line()).collect()
    }

    #[test]
    fn multibyte_char_split_across_chunks_decodes_intact() {
        let bytes = "data: caf\u{e9} \u{1f600}\n".as_bytes();
        let mut r = LineReader::new(1024);
        // Split inside both multi-byte sequences.
        for chunk in [&bytes[..9], &bytes[9..13], &bytes[13..]] {
            r.push(chunk).unwrap();
        }
        assert_eq!(drain(&mut r), vec!["data: caf\u{e9} \u{1f600}".to_string()]);
    }

    #[test]
    fn crlf_blank_lines_and_partial_tail() {
        let mut r = LineReader::new(1024);
        r.push(b"a\r\n\r\nb").unwrap();
        assert_eq!(drain(&mut r), vec!["a", ""]);
        r.push(b"c\n").unwrap();
        assert_eq!(drain(&mut r), vec!["bc"]);
        assert_eq!(r.next_line(), None);
    }

    #[test]
    fn unterminated_line_is_capped_but_terminated_lines_are_not() {
        let mut r = LineReader::new(8);
        // Many complete lines in one chunk never count against the cap.
        r.push(&b"0123456\n".repeat(100)).unwrap();
        assert_eq!(drain(&mut r).len(), 100);
        r.push(b"12345678").unwrap();
        assert_eq!(r.push(b"9"), Err(LineTooLong { tail_bytes: 9 }));
    }

    /// The quadratic defect: 400k newlines in one chunk. Re-slicing a String
    /// per line copies ~80 GB here; the byte reader is linear.
    #[test]
    fn all_newline_chunk_is_linear() {
        let mut r = LineReader::new(1024);
        let started = std::time::Instant::now();
        r.push(&vec![b'\n'; 400_000]).unwrap();
        let mut n = 0usize;
        while r.next_line().is_some() {
            n += 1;
        }
        assert_eq!(n, 400_000);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn one_byte_chunks_of_a_long_line_do_not_rescan() {
        let mut r = LineReader::new(1 << 20);
        for _ in 0..200_000 {
            r.push(b"x").unwrap();
            assert!(r.next_line().is_none());
        }
        r.push(b"\n").unwrap();
        assert_eq!(r.next_line().map(|l| l.len()), Some(200_000));
    }
}
