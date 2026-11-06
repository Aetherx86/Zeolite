//! Binary wire format for Raft messages.
//!
//! Decoding treats its input as hostile. Every length is checked against the bytes
//! actually present before anything is allocated, so a forged count cannot trigger a
//! huge allocation.

use crate::core::{Entry, Envelope, Message, Snapshot};

#[derive(Debug, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    UnknownTag(u8),
    TrailingBytes,
    InvalidBool(u8),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Truncated => write!(f, "message is truncated"),
            CodecError::UnknownTag(t) => write!(f, "unknown message tag {t}"),
            CodecError::TrailingBytes => write!(f, "trailing bytes after message"),
            CodecError::InvalidBool(b) => write!(f, "invalid boolean byte {b}"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Smallest possible encoded entry: term, index and a data length.
const MIN_ENTRY_LEN: usize = 8 + 8 + 4;

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.buf.len() < n {
            return Err(CodecError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        let mut out = [0u8; 8];
        out.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(out))
    }

    fn bool(&mut self) -> Result<bool, CodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(CodecError::InvalidBool(other)),
        }
    }

    fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn entry(&mut self) -> Result<Entry, CodecError> {
        Ok(Entry {
            term: self.u64()?,
            index: self.u64()?,
            data: self.bytes()?,
        })
    }
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

pub(crate) fn put_entry(out: &mut Vec<u8>, e: &Entry) {
    out.extend_from_slice(&e.term.to_le_bytes());
    out.extend_from_slice(&e.index.to_le_bytes());
    put_bytes(out, &e.data);
}

pub(crate) fn get_entry(buf: &[u8]) -> Result<Entry, CodecError> {
    let mut r = Reader { buf };
    let e = r.entry()?;
    if !r.buf.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(e)
}

pub fn encode(env: &Envelope) -> Vec<u8> {
    let mut o = Vec::with_capacity(64);
    o.extend_from_slice(&env.from.to_le_bytes());
    o.extend_from_slice(&env.to.to_le_bytes());
    let put_u64 = |o: &mut Vec<u8>, v: u64| o.extend_from_slice(&v.to_le_bytes());
    match &env.msg {
        Message::PreVote {
            term,
            last_index,
            last_term,
        } => {
            o.push(1);
            put_u64(&mut o, *term);
            put_u64(&mut o, *last_index);
            put_u64(&mut o, *last_term);
        }
        Message::PreVoteResp { term, granted } => {
            o.push(2);
            put_u64(&mut o, *term);
            o.push(u8::from(*granted));
        }
        Message::Vote {
            term,
            last_index,
            last_term,
        } => {
            o.push(3);
            put_u64(&mut o, *term);
            put_u64(&mut o, *last_index);
            put_u64(&mut o, *last_term);
        }
        Message::VoteResp { term, granted } => {
            o.push(4);
            put_u64(&mut o, *term);
            o.push(u8::from(*granted));
        }
        Message::Append {
            term,
            prev_index,
            prev_term,
            entries,
            commit,
        } => {
            o.push(5);
            put_u64(&mut o, *term);
            put_u64(&mut o, *prev_index);
            put_u64(&mut o, *prev_term);
            put_u64(&mut o, *commit);
            o.extend_from_slice(&(entries.len() as u32).to_le_bytes());
            for e in entries {
                put_entry(&mut o, e);
            }
        }
        Message::AppendResp {
            term,
            success,
            match_index,
            hint,
        } => {
            o.push(6);
            put_u64(&mut o, *term);
            o.push(u8::from(*success));
            put_u64(&mut o, *match_index);
            put_u64(&mut o, *hint);
        }
        Message::Snapshot { term, snapshot } => {
            o.push(7);
            put_u64(&mut o, *term);
            put_u64(&mut o, snapshot.last_index);
            put_u64(&mut o, snapshot.last_term);
            put_bytes(&mut o, &snapshot.data);
        }
        Message::SnapshotResp { term, index } => {
            o.push(8);
            put_u64(&mut o, *term);
            put_u64(&mut o, *index);
        }
    }
    o
}

pub fn decode(buf: &[u8]) -> Result<Envelope, CodecError> {
    let mut r = Reader { buf };
    let from = r.u64()?;
    let to = r.u64()?;
    let tag = r.u8()?;
    let msg = match tag {
        1 => Message::PreVote {
            term: r.u64()?,
            last_index: r.u64()?,
            last_term: r.u64()?,
        },
        2 => Message::PreVoteResp {
            term: r.u64()?,
            granted: r.bool()?,
        },
        3 => Message::Vote {
            term: r.u64()?,
            last_index: r.u64()?,
            last_term: r.u64()?,
        },
        4 => Message::VoteResp {
            term: r.u64()?,
            granted: r.bool()?,
        },
        5 => {
            let term = r.u64()?;
            let prev_index = r.u64()?;
            let prev_term = r.u64()?;
            let commit = r.u64()?;
            let count = r.u32()? as usize;
            if count > r.buf.len() / MIN_ENTRY_LEN {
                return Err(CodecError::Truncated);
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                entries.push(r.entry()?);
            }
            Message::Append {
                term,
                prev_index,
                prev_term,
                entries,
                commit,
            }
        }
        6 => Message::AppendResp {
            term: r.u64()?,
            success: r.bool()?,
            match_index: r.u64()?,
            hint: r.u64()?,
        },
        7 => Message::Snapshot {
            term: r.u64()?,
            snapshot: Snapshot {
                last_index: r.u64()?,
                last_term: r.u64()?,
                data: r.bytes()?,
            },
        },
        8 => Message::SnapshotResp {
            term: r.u64()?,
            index: r.u64()?,
        },
        other => return Err(CodecError::UnknownTag(other)),
    };
    if !r.buf.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(Envelope { from, to, msg })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Message> {
        let entries = vec![
            Entry {
                term: 3,
                index: 7,
                data: vec![],
            },
            Entry {
                term: 3,
                index: 8,
                data: b"payload".to_vec(),
            },
        ];
        vec![
            Message::PreVote {
                term: 1,
                last_index: 2,
                last_term: 3,
            },
            Message::PreVoteResp {
                term: 4,
                granted: true,
            },
            Message::Vote {
                term: 5,
                last_index: 6,
                last_term: 7,
            },
            Message::VoteResp {
                term: 8,
                granted: false,
            },
            Message::Append {
                term: 9,
                prev_index: 6,
                prev_term: 2,
                entries,
                commit: 5,
            },
            Message::AppendResp {
                term: 9,
                success: true,
                match_index: 8,
                hint: 0,
            },
            Message::Snapshot {
                term: 10,
                snapshot: Snapshot {
                    last_index: 100,
                    last_term: 9,
                    data: vec![1, 2, 3],
                },
            },
            Message::SnapshotResp {
                term: 10,
                index: 100,
            },
        ]
    }

    #[test]
    fn round_trips_every_message() {
        for msg in samples() {
            let env = Envelope {
                from: 1,
                to: 2,
                msg,
            };
            assert_eq!(decode(&encode(&env)).unwrap(), env);
        }
    }

    #[test]
    fn every_truncation_is_rejected() {
        for msg in samples() {
            let bytes = encode(&Envelope {
                from: 1,
                to: 2,
                msg,
            });
            for cut in 0..bytes.len() {
                assert!(
                    decode(&bytes[..cut]).is_err(),
                    "accepted a {cut}-byte prefix"
                );
            }
        }
    }

    #[test]
    fn rejects_trailing_bytes_and_unknown_tags() {
        let mut bytes = encode(&Envelope {
            from: 1,
            to: 2,
            msg: Message::VoteResp {
                term: 1,
                granted: true,
            },
        });
        bytes.push(0);
        assert_eq!(decode(&bytes), Err(CodecError::TrailingBytes));

        let mut unknown = vec![0u8; 16];
        unknown.push(99);
        assert_eq!(decode(&unknown), Err(CodecError::UnknownTag(99)));
    }

    #[test]
    fn forged_entry_count_does_not_allocate_or_panic() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.push(5);
        for _ in 0..4 {
            bytes.extend_from_slice(&0u64.to_le_bytes());
        }
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&bytes), Err(CodecError::Truncated));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut x = 0x1234_5678_9ABC_DEF0u64;
        for len in 0..400usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                buf.push(x as u8);
            }
            if buf.len() > 16 {
                buf[16] = (x % 10) as u8;
            }
            let _ = decode(&buf);
        }
    }
}
