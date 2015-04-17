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

impl Frame for PushPromiseFrame {
    /// The type that represents the flags that the particular `Frame` can take.
    /// This makes sure that only valid `Flag`s are used with each `Frame`.
    type FlagType = PushPromiseFlag;

    /// Creates a new `PushPromiseFrame` with the given `RawFrame` (i.e. header and
    /// payload), if possible.
    ///
    /// # Returns
    ///
    /// `None` if a valid `PushPromiseFrame` cannot be constructed from the given
    /// `RawFrame`. The stream ID *must not* be 0.
    ///
    /// Otherwise, returns a newly constructed `PushPromiseFrame`.
    fn from_raw(raw_frame: RawFrame) -> Option<PushPromiseFrame> {
        // Unpack the header
        let (len, frame_type, flags, stream_id) = raw_frame.header;
        // Check that the frame type is correct for this frame implementation
        if frame_type != 0x5 {
            return None;
        }
        // Check that the length given in the header matches the payload
        // length; if not, something went wrong and we do not consider this a
        // valid frame.
        if (len as usize) != raw_frame.payload.len() {
            return None;
        }
        // Check that the HEADERS frame is not associated to stream 0
        if stream_id == 0 {
            return None;
        }

        // First, we get a slice containing the actual payload, depending on if
        // the frame is padded.
        let padded = (flags & PushPromiseFlag::Padded.bitmask()) != 0;
        let (actual, pad_len) = if padded {
            match parse_padded_payload(&raw_frame.payload) {
                Some((data, pad_len)) => (data, Some(pad_len)),
                None => return None,
            }
        } else {
            (&raw_frame.payload[..], None)
        };

        // From the actual payload we extract the stream dependency info, if
        // the appropriate flag is set.
        let priority = (flags & PushPromiseFlag::Priority.bitmask()) != 0;
        let (data, stream_dep) = if priority {
            (&actual[5..], Some(StreamDependency::parse(&actual[..5])))
        } else {
            (actual, None)
        };

        Some(HeadersFrame {
            header_fragment: data.to_vec(),
            stream_id: stream_id,
            stream_dep: stream_dep,
            padding_len: pad_len,
            flags: flags,
        })
    }

    /// Tests if the given flag is set for the frame.
    fn is_set(&self, flag: PushPromiseFlag) -> bool {
        (self.flags & flag.bitmask()) != 0
    }

    /// Returns the `StreamId` of the stream to which the frame is associated.
    ///
    /// A `SettingsFrame` always has to be associated to stream `0`.
    fn get_stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns a `FrameHeader` based on the current state of the `Frame`.
    fn get_header(&self) -> FrameHeader {
        (self.payload_len(), 0x1, self.flags, self.stream_id)
    }

    /// Sets the given flag for the frame.
    fn set_flag(&mut self, flag: PushPromiseFlag) {
        self.flags |= flag.bitmask();
    }

    /// Returns a `Vec` with the serialized representation of the frame.
    ///
    /// # Panics
    ///
    /// If the `PushPromiseFlag::Priority` flag was set, but no stream dependency
    /// information is given (i.e. `stream_dep` is `None`).
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.payload_len() as usize);
        // First the header...
        buf.extend(pack_header(&self.get_header()).to_vec().into_iter());
        // Now the length of the padding, if any.
        let padded = self.is_set(PushPromiseFlag::Padded);
        if padded {
            buf.push(self.padding_len.unwrap_or(0));
        }
        // The stream dependency fields follow, if the priority flag is set
        if self.is_set(PushPromiseFlag::Priority) {
            let dep_buf = match self.stream_dep {
                Some(ref dep) => dep.serialize(),
                None => panic!("Priority flag set, but no dependency information given"),
            };
            buf.extend(dep_buf.to_vec().into_iter());
        }
        // Now the actual headers fragment
        buf.extend(self.header_fragment.clone().into_iter());
        // Finally, add the trailing padding, if required
        if padded {
            for _ in 0..self.padding_len.unwrap_or(0) { buf.push(0); }
        }

        buf
    }
}