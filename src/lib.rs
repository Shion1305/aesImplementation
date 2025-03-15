mod log;

const AES_BLOCK_SIZE: usize = 16;

#[cfg(test)]
prog_log!(aes_log, crate::Block);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block([u8; AES_BLOCK_SIZE]);

type Word = [u8; 4];
// State[column][row]
type State = [Word; 4];

#[derive(Debug, Clone, PartialEq, Eq)]
struct AES {
    key: Vec<u8>,
}

impl AES {
    fn new(key: &[u8]) -> Result<Self, &'static str> {
        if ![16, 24, 32].contains(&key.len()) {
            return Err("Invalid key length");
        }
        Ok(Self { key: key.to_vec() })
    }

    #[inline]
    fn block2state(block: Block) -> State {
        let mut state = [[0u8; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] = block.0[i * 4 + j];
            }
        }
        state
    }

    #[inline]
    fn state2block(state: State) -> Block {
        let mut block = [0u8; AES_BLOCK_SIZE];
        for i in 0..4 {
            for j in 0..4 {
                block[i * 4 + j] = state[i][j];
            }
        }
        Block(block)
    }

    #[inline]
    fn log_state(state: &State) {
        #[cfg(test)]
        aes_log::push(AES::state2block(*state));
    }

    fn encrypt_block(&self, block: Block) -> Block {
        let state = AES::block2state(block);
        AES::log_state(&state);

        // impl here

        AES::state2block(state)
    }
}

#[cfg(test)]
mod tests {
    use crate::{AES, Block, aes_log};

    fn setup() {
        aes_log::clear();
    }

    #[test]
    fn test() {
        setup();
        let plain_text = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*";
        let aes = AES::new(b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<")
            .ok()
            .unwrap();
        let _encrypted = aes.encrypt_block(Block(*plain_text));
        let log = aes_log::get();
        let expected = [plain_text];
        log.borrow()
            .iter()
            .zip(expected.into_iter())
            .for_each(|(a, b)| {
                assert_eq!(&a.0, b);
            });
    }

    #[test]
    fn fail_on_invalid_key_length() {
        setup();
        let key = [0u8; 10];
        let aes = AES::new(&key);
        assert_eq!(aes, Err("Invalid key length"));
    }
}
