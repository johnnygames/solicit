use super::super::StreamId;
use super::frames::{
    Frame,
    Flag,
    RawFrame,
    FrameHeader,
    pack_header,
};

/// An enum representing the flags that a `PushPromiseFrame` can have.
/// The integer representation associated to each variant is that flag's
/// bitmask.
///
/// HTTP/2 spec, section 6.6.
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Copy)]
pub enum PushPromiseFlag {
    EndHeaders = 0x4,
    Padded = 0x8,
}

impl Flag for PushPromiseFlag {
    #[inline]
    fn bitmask(&self) -> u8 {
        *self as u8
    }
}

pub struct PushPromiseFrame {
    pub promised_stream_id: StreamId,
    pub header_fragment: Vec<u8>,
    pub padding_len: Option<u8>,
    pub stream_id: StreamId,
    flags: u8,
}