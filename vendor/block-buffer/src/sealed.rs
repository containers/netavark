use super::{ArrayLength, Block};
use core::slice;

/// Sealed trait for buffer kinds.
pub trait Sealed {
    /// Invariant guaranteed by a buffer kind, i.e. with correct
    /// buffer code this function always returns true.
    fn invariant(pos: usize, block_size: usize) -> bool;

    /// Split input data into slice fo blocks and tail.
    fn split_blocks<N: ArrayLength<u8>>(data: &[u8]) -> (&[Block<N>], &[u8]);
}

impl Sealed for super::Eager {
    #[inline(always)]
    fn invariant(pos: usize, block_size: usize) -> bool {
        pos < block_size
    }

    #[inline(always)]
    fn split_blocks<N: ArrayLength<u8>>(data: &[u8]) -> (&[Block<N>], &[u8]) {
        let nb = data.len() / N::USIZE;
        let blocks_len = nb * N::USIZE;
        let tail_len = data.len() - blocks_len;
        // SAFETY: we guarantee that created slices do not point
        // outside of `data`
        unsafe {
            let blocks_ptr = data.as_ptr() as *const Block<N>;
            let tail_ptr = data.as_ptr().add(blocks_len);
            (
                slice::from_raw_parts(blocks_ptr, nb),
                slice::from_raw_parts(tail_ptr, tail_len),
            )
        }
    }
}

impl Sealed for super::Lazy {
    #[inline(always)]
    fn invariant(pos: usize, block_size: usize) -> bool {
        pos <= block_size
    }

    #[inline(always)]
    fn split_blocks<N: ArrayLength<u8>>(data: &[u8]) -> (&[Block<N>], &[u8]) {
        let nb = if data.is_empty() || data.len() % N::USIZE != 0 {
            data.len() / N::USIZE
        } else {
            data.len() / N::USIZE - 1
        };
        let blocks_len = nb * N::USIZE;
        let tail_len = data.len() - blocks_len;
        // SAFETY: we guarantee that created slices do not point
        // outside of `data`
        unsafe {
            let blocks_ptr = data.as_ptr() as *const Block<N>;
            let tail_ptr = data.as_ptr().add(blocks_len);
            (
                slice::from_raw_parts(blocks_ptr, nb),
                slice::from_raw_parts(tail_ptr, tail_len),
            )
        }
    }
}
