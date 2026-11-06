//! Durable Raft storage: a checksummed write-ahead log plus an atomically replaced
//! snapshot file.
//!
//! Recovery stops at the first record that fails its length or checksum test and
//! truncates the file there. That is the correct response to a torn write at the tail
//! of the log, which is the only corruption a crash alone can produce.

use crate::codec::{get_entry, put_entry};
use crate::core::{Entry, HardState, Index, Ready, Recovered, Snapshot};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const WAL_MAGIC: &[u8; 8] = b"ZEOWAL01";
const SNAP_MAGIC: &[u8; 8] = b"ZEOSNP01";
const KIND_HARD_STATE: u8 = 1;
const KIND_TRUNCATE: u8 = 2;
const KIND_ENTRY: u8 = 3;
const RECORD_HEADER: usize = 8;

pub struct Storage {
    dir: PathBuf,
    wal: File,
    /// Bytes dropped from a torn tail during the most recent recovery.
    pub recovered_torn_bytes: u64,
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn encode_record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(body.len() + 1);
    payload.push(kind);
    payload.extend_from_slice(body);
    let mut rec = Vec::with_capacity(RECORD_HEADER + payload.len());
    rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    rec.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    rec.extend_from_slice(&payload);
    rec
}

fn encode_hard_state(hs: &HardState) -> Vec<u8> {
    let mut b = Vec::with_capacity(25);
    b.extend_from_slice(&hs.term.to_le_bytes());
    match hs.voted_for {
        Some(id) => {
            b.push(1);
            b.extend_from_slice(&id.to_le_bytes());
        }
        None => {
            b.push(0);
            b.extend_from_slice(&0u64.to_le_bytes());
        }
    }
    b.extend_from_slice(&hs.commit.to_le_bytes());
    encode_record(KIND_HARD_STATE, &b)
}

fn le_u64(bytes: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(a)
}

fn apply_record(payload: &[u8], rec: &mut Recovered) -> Option<()> {
    let (&kind, body) = payload.split_first()?;
    match kind {
        KIND_HARD_STATE => {
            if body.len() != 25 || body[8] > 1 {
                return None;
            }
            rec.hard_state = HardState {
                term: le_u64(&body[0..8]),
                voted_for: (body[8] == 1).then(|| le_u64(&body[9..17])),
                commit: le_u64(&body[17..25]),
            };
        }
        KIND_TRUNCATE => {
            if body.len() != 8 {
                return None;
            }
            let from = le_u64(body);
            rec.entries.retain(|e| e.index < from);
        }
        KIND_ENTRY => {
            let entry = get_entry(body).ok()?;
            while rec.entries.last().is_some_and(|e| e.index >= entry.index) {
                rec.entries.pop();
            }
            rec.entries.push(entry);
        }
        _ => return None,
    }
    Some(())
}

fn replay(bytes: &[u8], rec: &mut Recovered) -> usize {
    let mut pos = WAL_MAGIC.len();
    while bytes.len() - pos >= RECORD_HEADER {
        let len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        let crc = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        let start = pos + RECORD_HEADER;
        let Some(end) = start.checked_add(len).filter(|end| *end <= bytes.len()) else {
            break;
        };
        let payload = &bytes[start..end];
        if crc32fast::hash(payload) != crc || apply_record(payload, rec).is_none() {
            break;
        }
        pos = end;
    }
    pos
}

/// Truncates through a separate handle, because Windows refuses to change the length of a
/// file through a handle opened in append mode.
fn truncate_file(path: &Path, len: u64) -> io::Result<()> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(len)?;
    file.sync_data()
}

fn read_snapshot(path: &Path) -> io::Result<Option<Snapshot>> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    let header = SNAP_MAGIC.len() + 8 + 8 + 4;
    if bytes.len() < header || &bytes[..SNAP_MAGIC.len()] != SNAP_MAGIC {
        return Err(invalid("snapshot file has a bad header"));
    }
    let last_index = le_u64(&bytes[8..16]);
    let last_term = le_u64(&bytes[16..24]);
    let crc = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    let data = &bytes[header..];
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[8..24]);
    hasher.update(data);
    if hasher.finalize() != crc {
        // The file is renamed into place only after a flush, so a bad checksum here
        // is real media corruption. Starting from an empty state would silently
        // lose committed data, so refuse instead.
        return Err(invalid("snapshot file failed its checksum"));
    }
    Ok(Some(Snapshot {
        last_index,
        last_term,
        data: data.to_vec(),
    }))
}

impl Storage {
    /// Opens or creates storage in `dir` and returns the state to start Raft from.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<(Storage, Recovered)> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let _ = fs::remove_file(dir.join("wal.tmp"));
        let _ = fs::remove_file(dir.join("snapshot.tmp"));

        let mut recovered = Recovered {
            snapshot: read_snapshot(&dir.join("snapshot"))?,
            ..Recovered::default()
        };

        let wal_path = dir.join("wal");
        let mut wal = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&wal_path)?;
        let mut bytes = Vec::new();
        wal.read_to_end(&mut bytes)?;

        let mut torn = 0u64;
        if bytes.is_empty() {
            wal.write_all(WAL_MAGIC)?;
            wal.sync_data()?;
            sync_dir(&dir)?;
        } else if bytes.len() < WAL_MAGIC.len() {
            // Crashed while writing the magic, so no record can have been written.
            torn = bytes.len() as u64;
            truncate_file(&wal_path, 0)?;
            wal.write_all(WAL_MAGIC)?;
            wal.sync_data()?;
        } else {
            if &bytes[..WAL_MAGIC.len()] != WAL_MAGIC {
                return Err(invalid("write-ahead log has a bad magic number"));
            }
            let good = replay(&bytes, &mut recovered);
            torn = (bytes.len() - good) as u64;
            if torn > 0 {
                truncate_file(&wal_path, good as u64)?;
            }
        }
        wal.seek(SeekFrom::End(0))?;

        Ok((
            Storage {
                dir,
                wal,
                recovered_torn_bytes: torn,
            },
            recovered,
        ))
    }

    /// Makes one [`Ready`] batch durable. Returns once the data is flushed.
    pub fn persist(&mut self, ready: &Ready) -> io::Result<()> {
        if let Some(snapshot) = &ready.install_snapshot {
            self.write_snapshot(snapshot)?;
        }
        let mut buf = Vec::new();
        if let Some(from) = ready.truncate_from {
            buf.extend_from_slice(&encode_record(KIND_TRUNCATE, &from.to_le_bytes()));
        }
        for e in &ready.entries {
            let mut body = Vec::with_capacity(e.data.len() + 20);
            put_entry(&mut body, e);
            buf.extend_from_slice(&encode_record(KIND_ENTRY, &body));
        }
        if let Some(hs) = &ready.hard_state {
            buf.extend_from_slice(&encode_hard_state(hs));
        }
        if !buf.is_empty() {
            self.wal.write_all(&buf)?;
            self.wal.sync_data()?;
        }
        Ok(())
    }

    fn write_snapshot(&self, snapshot: &Snapshot) -> io::Result<()> {
        let tmp = self.dir.join("snapshot.tmp");
        let mut f = File::create(&tmp)?;
        f.write_all(SNAP_MAGIC)?;
        let mut meta = Vec::with_capacity(16);
        meta.extend_from_slice(&snapshot.last_index.to_le_bytes());
        meta.extend_from_slice(&snapshot.last_term.to_le_bytes());
        f.write_all(&meta)?;
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&meta);
        hasher.update(&snapshot.data);
        f.write_all(&hasher.finalize().to_le_bytes())?;
        f.write_all(&snapshot.data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, self.dir.join("snapshot"))?;
        sync_dir(&self.dir)
    }

    /// Persists a locally produced snapshot and rewrites the log so that it holds
    /// only `retained`, the entries after the snapshot.
    pub fn save_snapshot(
        &mut self,
        snapshot: &Snapshot,
        retained: &[Entry],
        hard_state: HardState,
    ) -> io::Result<()> {
        self.write_snapshot(snapshot)?;

        let tmp = self.dir.join("wal.tmp");
        let mut out = File::create(&tmp)?;
        let mut buf = WAL_MAGIC.to_vec();
        for e in retained {
            debug_assert!(e.index > snapshot.last_index);
            let mut body = Vec::with_capacity(e.data.len() + 20);
            put_entry(&mut body, e);
            buf.extend_from_slice(&encode_record(KIND_ENTRY, &body));
        }
        buf.extend_from_slice(&encode_hard_state(&hard_state));
        out.write_all(&buf)?;
        out.sync_all()?;
        drop(out);

        // Windows cannot rename over a file that is still open, so the old handle is
        // replaced with a handle on the temporary file first.
        self.wal = OpenOptions::new().read(true).open(&tmp)?;
        let wal_path = self.dir.join("wal");
        fs::rename(&tmp, &wal_path)?;
        sync_dir(&self.dir)?;
        self.wal = OpenOptions::new().read(true).append(true).open(&wal_path)?;
        self.wal.seek(SeekFrom::End(0))?;
        Ok(())
    }

    pub fn wal_len(&self) -> io::Result<u64> {
        Ok(self.wal.metadata()?.len())
    }
}

/// Convenience for tests and tooling that need the highest stored index.
pub fn last_index(entries: &[Entry], snapshot: Option<&Snapshot>) -> Index {
    entries
        .last()
        .map(|e| e.index)
        .or_else(|| snapshot.map(|s| s.last_index))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zeolite-raft-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn entry(term: u64, index: u64, data: &[u8]) -> Entry {
        Entry {
            term,
            index,
            data: data.to_vec(),
        }
    }

    #[test]
    fn replays_appends_truncation_and_hard_state() {
        let dir = temp_dir("replay");
        let (mut s, rec) = Storage::open(&dir).unwrap();
        assert!(rec.entries.is_empty());
        s.persist(&Ready {
            entries: vec![entry(1, 1, b"a"), entry(1, 2, b"b"), entry(1, 3, b"c")],
            hard_state: Some(HardState {
                term: 1,
                voted_for: Some(7),
                commit: 1,
            }),
            ..Ready::default()
        })
        .unwrap();
        s.persist(&Ready {
            truncate_from: Some(2),
            entries: vec![entry(2, 2, b"B")],
            hard_state: Some(HardState {
                term: 2,
                voted_for: None,
                commit: 2,
            }),
            ..Ready::default()
        })
        .unwrap();
        drop(s);

        let (_s, rec) = Storage::open(&dir).unwrap();
        assert_eq!(rec.entries, vec![entry(1, 1, b"a"), entry(2, 2, b"B")]);
        assert_eq!(
            rec.hard_state,
            HardState {
                term: 2,
                voted_for: None,
                commit: 2
            }
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_torn_tail_recovers_to_a_record_boundary() {
        let dir = temp_dir("torn");
        let (mut s, _) = Storage::open(&dir).unwrap();
        s.persist(&Ready {
            entries: vec![entry(1, 1, b"first")],
            ..Ready::default()
        })
        .unwrap();
        let good_len = s.wal_len().unwrap();
        s.persist(&Ready {
            entries: vec![entry(1, 2, b"second")],
            ..Ready::default()
        })
        .unwrap();
        let full_len = s.wal_len().unwrap();
        drop(s);

        let wal = dir.join("wal");
        let full = fs::read(&wal).unwrap();
        for cut in good_len..full_len {
            fs::write(&wal, &full[..cut as usize]).unwrap();
            let (s, rec) = Storage::open(&dir).unwrap();
            assert_eq!(rec.entries, vec![entry(1, 1, b"first")], "cut at {cut}");
            assert_eq!(s.recovered_torn_bytes, cut - good_len);
            assert_eq!(s.wal_len().unwrap(), good_len);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bit_flip_in_tail_record_is_detected() {
        let dir = temp_dir("flip");
        let (mut s, _) = Storage::open(&dir).unwrap();
        s.persist(&Ready {
            entries: vec![entry(1, 1, b"first"), entry(1, 2, b"second")],
            ..Ready::default()
        })
        .unwrap();
        drop(s);
        let wal = dir.join("wal");
        let mut bytes = fs::read(&wal).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x40;
        fs::write(&wal, bytes).unwrap();
        let (_s, rec) = Storage::open(&dir).unwrap();
        assert_eq!(rec.entries, vec![entry(1, 1, b"first")]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn snapshot_rewrites_the_log_and_survives_reopen() {
        let dir = temp_dir("snapshot");
        let (mut s, _) = Storage::open(&dir).unwrap();
        s.persist(&Ready {
            entries: vec![entry(1, 1, b"a"), entry(1, 2, b"b"), entry(2, 3, b"c")],
            ..Ready::default()
        })
        .unwrap();
        let snapshot = Snapshot {
            last_index: 2,
            last_term: 1,
            data: b"state".to_vec(),
        };
        let hs = HardState {
            term: 2,
            voted_for: Some(1),
            commit: 3,
        };
        s.save_snapshot(&snapshot, &[entry(2, 3, b"c")], hs)
            .unwrap();
        s.persist(&Ready {
            entries: vec![entry(2, 4, b"d")],
            ..Ready::default()
        })
        .unwrap();
        drop(s);

        let (_s, rec) = Storage::open(&dir).unwrap();
        assert_eq!(rec.snapshot, Some(snapshot));
        assert_eq!(rec.entries, vec![entry(2, 3, b"c"), entry(2, 4, b"d")]);
        assert_eq!(rec.hard_state, hs);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_snapshot_refuses_to_start() {
        let dir = temp_dir("badsnap");
        let (mut s, _) = Storage::open(&dir).unwrap();
        let snapshot = Snapshot {
            last_index: 2,
            last_term: 1,
            data: b"state".to_vec(),
        };
        s.save_snapshot(&snapshot, &[], HardState::default())
            .unwrap();
        drop(s);
        let path = dir.join("snapshot");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(Storage::open(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
