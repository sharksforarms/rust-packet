use deku::prelude::*;

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct SAckData {
    pub begin: u32,
    pub end: u32,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct TimestampData {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "big")]
pub enum TcpOption {
    #[deku(id = "0x00")]
    EOL,
    #[deku(id = "0x01")]
    NOP,
    #[deku(id = "0x02")]
    MSS { length: u8, value: u16 },
    #[deku(id = "0x03")]
    WScale { length: u8, value: u8 },
    #[deku(id = "0x04")]
    SAckOK { length: u8 },
    #[deku(id = "0x05")]
    SAck {
        #[deku(
            map = "|x: u8| -> Result<_, DekuError> { Ok(((x - 2) / 4) / 2) }",
            writer = "|x: u8, output_is_le: bool| -> Result<_, DekuError> {
                let val = ((x * 2) * 4) + 2;
                val.write(output_is_le, None)
            }(*length, output_is_le)"
        )]
        length: u8,
        #[deku(count = "length")]
        value: Vec<SAckData>,
    },
    #[deku(id = "0x08")]
    Timestamp { length: u8, value: TimestampData },
}
