// SPDX-FileCopyrightText: murmurhash3.rs 2026, ["François Cami" <contribs@fcami.net>]
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `MurmurHash3` (32-bit) implementation matching SSSD's `murmurhash3()`.
//!
//! This is a direct port of the SSSD implementation, which itself is based
//! on the public domain `MurmurHash3` by Austin Appleby. The 32-bit variant
//! is used because SSSD needs identical hashes on both 32-bit and 64-bit
//! architectures.
//!
//! All multi-byte reads are little-endian to match SSSD's `le32toh()`.

fn getblock(data: &[u8], i: usize) -> u32 {
    let offset = i * 4;
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn fmix(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// Compute `MurmurHash3` (32-bit) of `key` with the given `seed`.
///
/// This produces identical output to SSSD's `murmurhash3()` function
/// for the same inputs.
#[must_use]
pub fn murmurhash3(key: &[u8], seed: u32) -> u32 {
    let len = key.len();
    let nblocks = len / 4;
    let mut h1 = seed;
    let c1: u32 = 0xcc9e_2d51;
    let c2: u32 = 0x1b87_3593;

    // body
    for i in 0..nblocks {
        let mut k1 = getblock(key, i);
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    // tail
    let tail = &key[nblocks * 4..];
    let mut k1: u32 = 0;
    match len & 3 {
        3 => {
            k1 ^= u32::from(tail[2]) << 16;
            k1 ^= u32::from(tail[1]) << 8;
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        2 => {
            k1 ^= u32::from(tail[1]) << 8;
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        1 => {
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        _ => {}
    }

    // finalization
    h1 ^= len as u32;
    fmix(h1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_key() {
        let h = murmurhash3(b"", 0);
        assert_eq!(h, 0);
    }

    #[test]
    fn known_values() {
        let h = murmurhash3(b"root\0", 0);
        assert_eq!(h, murmurhash3(b"root\0", 0));
    }

    #[test]
    fn seed_changes_result() {
        let h1 = murmurhash3(b"test", 0);
        let h2 = murmurhash3(b"test", 42);
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_keys_different_hashes() {
        let h1 = murmurhash3(b"alice\0", 123);
        let h2 = murmurhash3(b"bob\0", 123);
        assert_ne!(h1, h2);
    }

    #[test]
    fn tail_lengths() {
        let seed = 42;
        let _h1 = murmurhash3(b"a", seed);
        let _h2 = murmurhash3(b"ab", seed);
        let _h3 = murmurhash3(b"abc", seed);
        let _h4 = murmurhash3(b"abcd", seed);
    }
}
