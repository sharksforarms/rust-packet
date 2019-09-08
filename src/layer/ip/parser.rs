use nom::bits::streaming::take as take_bits;
use nom::IResult;

pub fn parse_ipv4_header(
    input: &[u8],
) -> IResult<(&[u8], usize), (u8, u8, u8, u8, u16, u16, u8, u16, u8, u8, u16, u32, u32)> {
    let (rest, version): (_, u8) = take_bits(4usize)((input, 0usize))?;
    let (rest, ihl): (_, u8) = take_bits(4usize)(rest)?;
    let (rest, dscp): (_, u8) = take_bits(6usize)(rest)?;
    let (rest, ecn): (_, u8) = take_bits(2usize)(rest)?;
    let (rest, length): (_, u16) = take_bits(16usize)(rest)?;
    let (rest, identification): (_, u16) = take_bits(16usize)(rest)?;
    let (rest, flags): (_, u8) = take_bits(3usize)(rest)?;
    let (rest, offset): (_, u16) = take_bits(13usize)(rest)?;
    let (rest, ttl): (_, u8) = take_bits(8usize)(rest)?;
    let (rest, protocol): (_, u8) = take_bits(8usize)(rest)?;
    let (rest, checksum): (_, u16) = take_bits(16usize)(rest)?;
    let (rest, src): (_, u32) = take_bits(32usize)(rest)?;
    let (rest, dst): (_, u32) = take_bits(32usize)(rest)?;

    Ok((
        rest,
        (
            version,
            ihl,
            dscp,
            ecn,
            length,
            identification,
            flags,
            offset,
            ttl,
            protocol,
            checksum,
            src,
            dst,
        ),
    ))
}

pub fn parse_ipv6_header(
    input: &[u8],
) -> IResult<(&[u8], usize), (u8, u8, u8, u32, u16, u8, u8, u128, u128)> {
    let (rest, version): (_, u8) = take_bits(4usize)((input, 0usize))?;
    let (rest, ds): (_, u8) = take_bits(6usize)(rest)?;
    let (rest, ecn): (_, u8) = take_bits(2usize)(rest)?;
    let (rest, label): (_, u32) = take_bits(20usize)(rest)?;
    let (rest, length): (_, u16) = take_bits(16usize)(rest)?;
    let (rest, next_header): (_, u8) = take_bits(8usize)(rest)?;
    let (rest, hop_limit): (_, u8) = take_bits(8usize)(rest)?;
    let (rest, src): (_, u128) = take_bits(128usize)(rest)?;
    let (rest, dst): (_, u128) = take_bits(128usize)(rest)?;

    Ok((
        rest,
        (
            version,
            ds,
            ecn,
            label,
            length,
            next_header,
            hop_limit,
            src,
            dst,
        ),
    ))
}
