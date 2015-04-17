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

impl PushPromiseFrame {
    pub fn new (fragment: Vec<u8>, stream_id: StreamId, promised_stream_id: StreamId) -> PushPromiseFrame {
        PushPromiseFrame {
            promised_stream_id: promised_stream_id,
            header_fragment: fragment,
            padding_len: None,
            stream_id: StreamId,
            flags: 0,
        }
    }

    /// Returns whether this frame ends the headers. If not, there MUST be a
    /// number of follow up CONTINUATION frames that send the rest of the
    /// header data.
    pub fn is_headers_end(&self) -> bool {
        self.is_set(PushPromiseFlag::EndHeaders)
    }

    /// Sets the padding length for the frame, as well as the corresponding
    /// Padded flag.
    pub fn set_padding(&mut self, padding_len: u8) {
        self.padding_len = Some(padding_len);
        self.set_flag(PushPromiseFlag::Padded);
    }

    /// Returns the length of the payload of the current frame, including any
    /// possible padding in the number of bytes.
    fn payload_len(&self) -> u32 {
        let padding = if self.is_set(PushPromiseFlag::Padded) {
            1 + self.padding_len.unwrap_or(0) as u32
        } else {
            0
        };
        self.header_fragment.len() as u32 + padding
    }
}