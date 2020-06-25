use deku::prelude::*;

#[derive(Debug, PartialEq, DekuWrite)]
pub struct Raw {
    pub data: Vec<u8>,
    #[deku(skip)]
    pub bit_offset: usize,
}

impl Raw {
    pub fn new(data: &[u8], bit_offset: usize) -> Self {
        Raw {
            data: data.to_vec(),
            bit_offset,
        }
    }
}

impl Default for Raw {
    fn default() -> Self {
        Raw::new([].as_ref(), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_write() {
        let input = [0xAAu8, 0xBB];
        let layer = Raw::new(input.as_ref(), 0);
        let ret_write = layer.to_bytes().unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_raw_default() {
        assert_eq!(
            Raw {
                data: vec![],
                bit_offset: 0,
            },
            Raw::default()
        )
    }
}
