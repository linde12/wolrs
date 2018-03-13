//! Parses an IEEE EUI-48 MAC address and continues to construct a
//! WakeOnLAN packet (so called "Magic Packet Technology")
use std::fmt;
use std::fmt::Display;
use std::error::Error;

const EUI48_LEN: usize = 6;
type Eui48 = [u8; EUI48_LEN];

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ParseError {
    /// Format is incorrect
    BadFormat,
    /// Length is incorrect. Should be either 12, 14 or 17.
    BadLength(usize),
    /// Character is not a valid hex character or one of -, : or .
    BadCharacter(char, usize),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::BadFormat => write!(f, "bad format"),
            ParseError::BadLength(size) => write!(f, "bad length of {}", size),
            ParseError::BadCharacter(c, size) => {
                write!(f, "bad character '{}' at index {}", c, size)
            }
        }
    }
}

impl Error for ParseError {
    fn description(&self) -> &str {
        "bad mac address"
    }
}

fn parse_mac(mac: &str) -> Result<Eui48, ParseError> {
    let mut eui: Eui48 = [0; EUI48_LEN];
    // whether the last nibble was the high_nibble
    let mut high_nibble = false;
    // offset in the eui array
    let mut offset = 0;

    match mac.len() {
        12 | 14 | 17 => {}
        _ => return Err(ParseError::BadLength(mac.len())),
    };

    for (idx, c) in mac.chars().enumerate() {
        if offset >= EUI48_LEN {
            return Err(ParseError::BadFormat);
        }
        match c {
            '0'...'9' | 'a'...'f' | 'A'...'F' => {
                match high_nibble {
                    false => {
                        high_nibble = true;
                        eui[offset] = (c.to_digit(16).unwrap() as u8) << 4;
                    }
                    true => {
                        high_nibble = false;
                        eui[offset] += c.to_digit(16).unwrap() as u8;
                        // 1 "hex byte" (two chars, e.g. AA) parsed
                        // increase target offset in eui
                        offset += 1;
                    }
                }
            }
            '-' | ':' | '.' => {} // ignore these characters
            _ => return Err(ParseError::BadCharacter(c, idx)),
        }
    }

    Ok(eui)
}

/// Creates a magic packet byte array for the given MAC address
///
/// Accepted formats are the following:
///
/// aa-bb-cc-dd-ee-ff
///
/// aa:bb:cc:dd:ee:ff
///
/// aa.bb.cc.dd.ee.ff
///
/// aabbccddeeff
pub fn create_magic_packet(mac: &str) -> Result<[u8; 102], ParseError> {
    let mut packet = [0xFFu8; 102];

    // parse MAC
    let mac = parse_mac(mac)?;

    // fill the packet with 16 occurrences of the MAC
    // starting at the 7th byte so that the first 6
    // bytes stay as 0xFF
    for i in 1..17 {
        for j in 0..6 {
            packet[i * 6 + j] = mac[j];
        }
    }

    Ok(packet)
}

#[test]
fn test_valid_ok() {
    assert!(create_magic_packet("ff:aa:bb:cc:dd:ee").is_ok());
    assert!(create_magic_packet("de-ad-be-ef-ba-be").is_ok());
    assert!(create_magic_packet("ca.11.ab.1e.ba.be").is_ok());
    assert!(create_magic_packet("ca.11:ab-1e.ba:be").is_ok());
    assert!(create_magic_packet("ca11ab1ebabe").is_ok());
}

#[test]
fn test_invalid_err() {
    // gibberish
    assert!(create_magic_packet("hello").is_err());
    // invalid characters
    assert!(create_magic_packet("he.js:an:cc:dd:ee").is_err());
    // too short
    assert!(create_magic_packet("ab:cd").is_err());
    // too long
    assert!(create_magic_packet("ab:cd:ab:cd:ab:cd:ab:cd:ab").is_err());
    // mixed length
    assert!(
        create_magic_packet("ca11ab1eba:be").is_err(),
        "mixed length not allowed"
    );
}

#[test]
fn test_magic() {
    let pkt = create_magic_packet("AA:aa:aa:aa:aa:aa").unwrap();

    // starts with padding
    let cmp = [255, 255, 255, 255, 255, 255];
    assert_eq!(&pkt[..6], &cmp);

    // follows with mac
    let cmp = [170, 170, 170, 170, 170, 170];
    assert_eq!(&pkt[6..12], &cmp);

    // ends with mac
    let cmp = [170, 170, 170, 170, 170, 170];
    assert_eq!(&pkt[102 - 6..102], &cmp);
}

#[test]
fn test_mac() {
    let pkt = parse_mac("aa:aa:aa:aa:aa:aa").unwrap();
    let mac = [170, 170, 170, 170, 170, 170];
    assert_eq!(&pkt[..], &mac);

    assert!(parse_mac("aa:aabbccddeeffaa").is_err(), "bad format");
}
