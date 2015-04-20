use super::super::StreamId;
use super::frames::{
    Frame,
    Flag,
    RawFrame,
    FrameHeader,
    pack_header,
    parse_padded_payload,
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

/// The struct represents the dependency information that can be attached to
/// a stream and sent within a 'PushPromiseFrame'.
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
pub struct PromisedStream {
    /// The ID of the stream that will be promised
    pub stream_id: StreamId,
}

impl PromisedStream {
    /// Creates a new `PromisedStream` with the given streamId
    pub fn new(stream_id: StreamId) -> PromisedStream {
        PromisedStream {
            stream_id: stream_id,
        }
    }

    /// Parses the first 4 bytes in the buffer as a `PromisedStream`.
    /// (Each 4-byte sequence is always decodable into a promised stream
    /// structure).
    ///
    pub fn parse(buf: &[u8]) -> PromisedStream {
        let stream_id = {
            // Parse the first 4 bytes into a u32...
            let mut id = unpack_octets_4!(buf, 0, u32);
            // ...clear the first bit since the stream id is only 31 bits.
            id &= !(1 << 31);
            id
        };

        PromisedStream {
            stream_id: stream_id,
        }
    }

    /// Serializes the `PromisedStream` into a 4-byte buffer representing the
    /// promised stream description, as described in section 6.6. of the HTTP/2
    /// spec:
    ///
    /// ```notest
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-------------+-----------------------------------------------+
    /// |R|                 Promised Stream ID  (31)                    |
    /// +-+-------------+-----------------------------------------------+
    /// |  Header Fragment  (*)  |
    /// +-+-------------+-----------------------------------------------+
    /// ```
    ///
    pub fn serialize(&self) -> [u8; 4] {
        [
            (((self.stream_id >> 24) & 0x000000FF) as u8) | 0,
            (((self.stream_id >> 16) & 0x000000FF) as u8),
            (((self.stream_id >>  8) & 0x000000FF) as u8),
            (((self.stream_id >>  0) & 0x000000FF) as u8),
        ]
    }
}

pub struct PushPromiseFrame {
    pub promised_stream_id: Option<PromisedStream>,
    pub header_fragment: Vec<u8>,
    pub padding_len: Option<u8>,
    flags: u8,
}

impl PushPromiseFrame {
    pub fn new (fragment: Vec<u8>) -> PushPromiseFrame {
        PushPromiseFrame {
            header_fragment: fragment,
            promised_stream_id: None,
            padding_len: None,
            flags: 0,
        }
    }

    pub fn with_promise(
            fragment: Vec<u8>,
            promised_stream_id: PromisedStream) -> PushPromiseFrame {
        PushPromiseFrame {
            header_fragment: fragment,
            promised_stream_id: Some(promised_stream_id),
            padding_len: None,
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
        // The header fragment and the 4 octect PromisedStream stream_id combined
        self.header_fragment.len() as u32 + padding + 4
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
        // Here is where we parse the header_fragment from the PromisedStream
        // The Promised Stream always comes in first according the the diagrams
        // laid out in the spec as a u32, unpacked into 4 octets
        // Thus the header_fragment is all the data after the first 4 u8s
        let (data, promised_stream_id) = {
            (&actual[4..], Some(PromisedStream::parse(&actual[..4])))
        };

        Some(PushPromiseFrame {
            header_fragment: data.to_vec(),
            promised_stream_id: promised_stream_id,
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
    /// A `PushPromiseFrame` does not declar a stream_id so return '0'.
    fn get_stream_id(&self) -> StreamId {
        0
    }

    /// Returns a `FrameHeader` based on the current state of the `Frame`.
    fn get_header(&self) -> FrameHeader {
        (self.payload_len(), 0x5, self.flags, 0)
    }

    /// Sets the given flag for the frame.
    fn set_flag(&mut self, flag: PushPromiseFlag) {
        self.flags |= flag.bitmask();
    }

    /// Returns a `Vec` with the serialized representation of the frame.
    ///
    /// # Panics
    ///
    /// If there is no 'PromisedStream' information
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
        let promise_buf = match self.promised_stream_id {
            Some(ref promise) => promise.serialize(),
            None => panic!("No promised stream info!"),
        };
        buf.extend(promise_buf.to_vec().into_iter());
        // Now the actual headers fragment
        buf.extend(self.header_fragment.clone().into_iter());
        // Finally, add the trailing padding, if required
        if padded {
            for _ in 0..self.padding_len.unwrap_or(0) { buf.push(0); }
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::super::frames::{Frame, pack_header};
    use super::super::test::{build_test_frame, build_padded_frame_payload};
    use super::{PushPromiseFrame, PromisedStream};

    /// Tests that a simple PP frame is correctly parsed. The frame does
    /// not contain any padding information.
    #[test]
    fn test_push_frame_parse_simple() {
        let data = b"1234";
        let payload = data.to_vec();
        let header = (payload.len() as u32, 0x5, 0, 1);

        let frame = build_test_frame::<PushPromiseFrame>(&header, &payload);

        assert_eq!(frame.header_fragment, []);
        assert_eq!(frame.flags, 0);
        assert!(frame.padding_len.is_none());
    }

    /// Tests that a PP frame with padding is correctly parsed.
    #[test]
    fn test_headers_frame_parse_with_padding() {
        let data = b"1234567";
        let payload = build_padded_frame_payload(data, 6);
        let header = (payload.len() as u32, 0x5, 0x08, 1);

        let frame = build_test_frame::<PushPromiseFrame>(&header, &payload);

        assert_eq!(frame.flags, 8);
        assert_eq!(frame.get_stream_id(), 0);
        assert_eq!(frame.padding_len.unwrap(), 6);
    }

    /// Tests that a promised stream structure can be correctly parsed by the
    /// `PromisedStream::parse` method.
    #[test]
    fn test_parse_promised_stream() {
        {
            let buf = [0, 0, 0, 1];

            let dep = PromisedStream::parse(&buf);

            assert_eq!(dep.stream_id, 1);
        }
        {
            let buf = [0, 0, 1, 5];

            let dep = PromisedStream::parse(&buf);

            assert_eq!(dep.stream_id, unpack_octets_4!(buf, 0, u32));
        }
    }

    /// Tests that a promised stream structure can be correctly serialized by
    /// the `PromisedStream::serialize` method.
    #[test]
    fn test_serialize_promised_stream() {
        {
            let buf = [0, 0, 0, 1];
            let dep = PromisedStream::new(1);

            assert_eq!(buf, dep.serialize());
        }
    }

    /// Tests that a simple PP frame (no padding) gets
    /// correctly serialized.
    #[test]
    fn test_push_promise_frame_serialize_simple() {
        let mut payload: Vec<u8> = Vec::new();
        let data = b"1234567";
        let promise = [0, 0, 0, 1];
        payload.extend(promise.to_vec().into_iter());
        payload.extend(data.to_vec());
        let header = (payload.len() as u32, 0x5, 0, 0);
        let expected = {
            let headers = pack_header(&header);
            let mut res: Vec<u8> = Vec::new();
            res.extend(headers.to_vec().into_iter());
            res.extend(payload.into_iter());

            res
        };
        let newpromise = PromisedStream::new(1);
        let frame = PushPromiseFrame::with_promise(data.to_vec(), newpromise);
        let actual = frame.serialize();

        assert_eq!(expected, actual);
    }
}
