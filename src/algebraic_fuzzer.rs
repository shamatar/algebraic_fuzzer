use lain::prelude::*;
use lain::rand;
use lain::hexdump;

pub enum FieldElementInputCase {
    Valid(Vec<u8>),
    NotInField(Vec<u8>),
    InvalidEncoding(Vec<u8>)
}

pub enum ECPointInputCase {
    Valid(Vec<u8>),
    NotOnCurve(Vec<u8>),
    NotInGroup(Vec<u8>),
    InvalidEncoding(Vec<u8>)
}
