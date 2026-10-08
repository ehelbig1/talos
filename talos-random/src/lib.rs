//! Bytes from the operating system's random source.
//!
//! Every key, nonce, salt and bearer token in the workspace is made from
//! bytes drawn here: `getrandom(2)` on Linux, `getentropy(2)` on macOS,
//! through the `rand` crate's interface to them. Nothing in this crate keeps
//! state, seeds a generator or stretches a seed; each call asks the kernel.
//!
//! # When the source fails
//!
//! It panics. A caller holding a buffer the kernel did not fill holds a
//! buffer of zeros, and a key made of zeros is worse than no key: it works.
//! The source fails only when the process cannot reach it at all (a sandbox
//! that denies the system call, a kernel without it), which is not something
//! a caller can handle by trying again.
//!
//! # What does not belong here
//!
//! Jitter, sampling, a shuffle: anything where a guessable value costs
//! nothing uses `rand`'s thread-local generator directly, and saves the
//! system call.

/// Fill `buf` from the operating system's random source.
///
/// # Panics
///
/// If the operating system cannot provide the bytes. See the crate
/// documentation for why that is not returned as an error.
pub fn fill(buf: &mut [u8]) {
    use rand::TryRng as _;
    rand::rngs::SysRng
        .try_fill_bytes(buf)
        .expect("the operating system's random source is unavailable");
}

/// `N` bytes from the operating system's random source.
///
/// # Panics
///
/// As [`fill`].
#[must_use]
pub fn bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_is_overwritten_whatever_it_held() {
        // 64 bytes left exactly as they were has probability 2^-512.
        for start in [0x00u8, 0xff, 0xa5] {
            let mut buf = [start; 64];
            fill(&mut buf);
            assert_ne!(buf, [start; 64]);
        }
    }

    #[test]
    fn two_draws_differ() {
        let draws: Vec<[u8; 32]> = (0..64).map(|_| bytes()).collect();
        for (i, a) in draws.iter().enumerate() {
            for b in &draws[i + 1..] {
                assert_ne!(a, b, "the same 32 bytes were drawn twice");
            }
        }
    }

    #[test]
    fn every_byte_of_the_buffer_is_written_not_a_prefix_of_it() {
        // A source that fills only part of what it is given leaves the rest
        // at the value it started with. Over 64 draws, a position that never
        // moves off zero has probability 256^-64.
        for len in [1usize, 2, 7, 31, 32, 33, 255, 256, 257, 4096, 70_000] {
            let mut ever_nonzero = vec![false; len];
            for _ in 0..64 {
                let mut buf = vec![0u8; len];
                fill(&mut buf);
                for (seen, byte) in ever_nonzero.iter_mut().zip(&buf) {
                    *seen |= *byte != 0;
                }
            }
            assert!(
                ever_nonzero.iter().all(|seen| *seen),
                "a byte of a {len}-byte buffer was never written"
            );
        }
    }

    #[test]
    fn the_bits_are_balanced() {
        // One megabyte: 8,388,608 bits, standard deviation 1,448. A source
        // that is constant, counting, or biased by a percent is far outside
        // ten of them; a working one is outside with probability ~1e-23.
        let mut buf = vec![0u8; 1 << 20];
        fill(&mut buf);
        let ones: u64 = buf.iter().map(|b| u64::from(b.count_ones())).sum();
        let expected = (buf.len() as u64) * 4;
        assert!(
            ones.abs_diff(expected) < 14_480,
            "{ones} one-bits of {}",
            buf.len() * 8
        );
    }

    #[test]
    fn nothing_to_fill_is_not_an_error() {
        fill(&mut []);
        assert_eq!(bytes::<0>(), [0u8; 0]);
    }
}
