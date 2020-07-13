/*!
Raw layer

A Raw layer represents un-parsed data or application data such as a UDP payload
*/
use deku::prelude::*;

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
pub struct Raw {
    #[deku(reader = "Raw::reader(rest)")]
    pub data: Vec<u8>,
    #[deku(skip)]
    pub bit_offset: usize,
}

impl Raw {
    fn reader(rest: &BitSlice<Msb0, u8>) -> Result<(&BitSlice<Msb0, u8>, Vec<u8>), DekuError> {
        // read all the rest
        let ret = rest.as_slice().to_vec();
        let (empty, _rest) = rest.split_at(0);
        Ok((empty, ret))
    }
}

impl Default for Raw {
    fn default() -> Self {
        Raw {
            data: vec![],
            bit_offset: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_write() {
        let input = [0xAAu8, 0xBB];
        let layer = Raw {
            data: input.to_vec(),
            bit_offset: 0xFF,
        };
        let ret_write = layer.to_bytes().unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_raw_read() {
        let input = [0xAAu8, 0xBB];
        let (rest, layer) = Raw::from_bytes((input.as_ref(), 0)).unwrap();

        assert_eq!(
            Raw {
                data: input.to_vec(),
                bit_offset: 0,
            },
            layer
        );

        assert_eq!((0, 0), (rest.0.len(), rest.1));
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
