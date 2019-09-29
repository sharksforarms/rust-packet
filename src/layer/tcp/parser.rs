use nom::bits::bytes;
use nom::bits::streaming::{tag, take as take_bits};
use nom::bytes::streaming::take as take_bytes;
use nom::combinator::verify;
use nom::sequence::tuple;
use nom::IResult;

#[derive(Debug, PartialEq)]
pub struct SackPtr {
    pub begin: u32,
    pub end: u32,
}

#[derive(Debug, PartialEq)]
pub enum TcpOption {
    EOL,
    NOP,
    Mss(u16),
    Ws(u8),
    SackPerm,
    Sack(Vec<SackPtr>),
    Timestamp((u32, u32)),
    Unknown(Vec<u8>),
}

pub fn parse_tcp_header(
    input: &[u8],
) -> IResult<(&[u8], usize), (u16, u16, u32, u32, u8, u8, u16, u16, u16, u16)> {
    tuple((
        take_bits(16usize),                                          // sport
        take_bits(16usize),                                          // dport
        take_bits(32usize),                                          // seq
        take_bits(32usize),                                          // ack
        verify(take_bits(4usize), |v: &u8| (*v >= 5) && (*v <= 15)), // offset
        take_bits(3usize),                                           // reserved
        take_bits(9usize),                                           // flags
        take_bits(16usize),                                          // window
        take_bits(16usize),                                          // checksum
        take_bits(16usize),                                          // urgptr
    ))((input, 0usize))
}

pub fn parse_tcp_options(
    rest: (&[u8], usize),
    offset: u8,
) -> IResult<(&[u8], usize), Vec<TcpOption>> {
    let options_count: usize = offset as usize - 5;
    let options_size: usize = (options_count * 32) / 8;
    let (rest, option_data) = bytes::<_, _, (_, _), _, _>(take_bytes(options_size))(rest)?;
    let mut option_data = (option_data, 0usize);

    let mut options: Vec<TcpOption> = Vec::with_capacity(offset as usize - 5);
    // TODO: Might be padded with 0s
    while !option_data.0.is_empty() {
        let (option_data2, option) = parse_single_option(option_data)?;
        options.push(option);
        option_data = option_data2;
    }

    Ok((rest, options))
}

fn parse_single_option(rest: (&[u8], usize)) -> IResult<(&[u8], usize), TcpOption> {
    let (rest, kind): (_, u8) = take_bits(8usize)(rest)?;
    match kind {
        0x0 => Ok((rest, TcpOption::EOL)),
        0x1 => Ok((rest, TcpOption::NOP)),
        0x2 => {
            let (rest, _size): (_, usize) = tag(4usize, 8usize)(rest)?;
            let (rest, mss): (_, u16) = take_bits(16usize)(rest)?;

            Ok((rest, TcpOption::Mss(mss)))
        }
        0x3 => {
            let (rest, _size): (_, usize) = tag(3usize, 8usize)(rest)?;
            let (rest, ws): (_, u8) = take_bits(8usize)(rest)?;

            Ok((rest, TcpOption::Ws(ws)))
        }
        0x4 => {
            let (rest, _size): (_, usize) = tag(2usize, 8usize)(rest)?;
            Ok((rest, TcpOption::SackPerm))
        }
        0x5 => {
            let (rest, size): (_, usize) = verify(take_bits(8usize), |v: &usize| {
                (*v == 10) || (*v == 18) || (*v == 26) || (*v == 34)
            })(rest)?;
            let ptr_count: usize = (((size - 2) * 8) / 32) / 2; // TODO figure this out better

            let mut rest = rest;
            let mut sackptrs: Vec<SackPtr> = Vec::with_capacity(ptr_count);
            for _ in 0..ptr_count {
                let (r, begin): (_, u32) = take_bits(32usize)(rest)?;
                let (r, end): (_, u32) = take_bits(32usize)(r)?;
                let sackptr = SackPtr { begin, end };
                sackptrs.push(sackptr);

                rest = r;
            }

            Ok((rest, TcpOption::Sack(sackptrs)))
        }
        0x8 => {
            let (rest, _size): (_, usize) = tag(10usize, 8usize)(rest)?;
            let (rest, timestamp): (_, u32) = take_bits(32usize)(rest)?;
            let (rest, prev_timestamp): (_, u32) = take_bits(32usize)(rest)?;

            Ok((rest, TcpOption::Timestamp((timestamp, prev_timestamp))))
        }
        _ => {
            // TODO maybe error out instead? are non-standard tcp options a thing?
            let (rest, size): (_, usize) = verify(take_bits(8usize), |v: &usize| *v >= 2)(rest)?;
            let size: usize = size - 2; // 1 byte for kind and one byte for length inclusive

            let mut rest = rest;
            let mut data = Vec::with_capacity(size);
            for _ in 1..size {
                let (r, byte): (_, u8) = take_bits(8usize)(rest)?;
                data.push(byte);
                rest = r;
            }

            Ok((rest, TcpOption::Unknown(data)))
        }
    }
}
