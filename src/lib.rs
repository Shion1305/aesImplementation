mod log;

const AES_BLOCK_SIZE: usize = 16;

#[cfg(test)]
prog_log!(aes_log, u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block([u8; AES_BLOCK_SIZE]);

#[cfg(test)]
mod tests {}
