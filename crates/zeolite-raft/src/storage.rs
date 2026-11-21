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

/// How many valid records of each kind a write-ahead log holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordCounts {
    pub hard_state: u64,
    pub truncate: u64,
    pub entry: u64,
}

impl RecordCounts {
    fn count(&mut self, kind: u8) {
        match kind {
            KIND_HARD_STATE => self.hard_state += 1,
            KIND_TRUNCATE => self.truncate += 1,
            _ => self.entry += 1,
        }
    }
}

fn apply_record(payload: &[u8], rec: &mut Recovered) -> Option<u8> {
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
    Some(kind)
}

fn replay(bytes: &[u8], rec: &mut Recovered, counts: &mut RecordCounts) -> usize {
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
        if crc32fast::hash(payload) != crc {
            break;
        }
        let Some(kind) = apply_record(payload, rec) else {
            break;
        };
        counts.count(kind);
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

fn read_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_snapshot(path: &Path) -> io::Result<Option<Snapshot>> {
    match read_file(path)? {
        Some(bytes) => parse_snapshot(&bytes).map(Some),
        None => Ok(None),
    }
}

fn parse_snapshot(bytes: &[u8]) -> io::Result<Snapshot> {
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
    Ok(Snapshot {
        last_index,
        last_term,
        data: data.to_vec(),
    })
}

/// A read-only report on a storage directory, produced by [`inspect`].
#[derive(Clone, Debug)]
pub struct Inspection {
    /// Size of the write-ahead log file.
    pub wal_bytes: u64,
    /// Bytes up to the end of the last valid record, including the magic number.
    pub valid_bytes: u64,
    /// Bytes after the last valid record, which [`Storage::open`] would truncate away.
    pub torn_bytes: u64,
    pub records: RecordCounts,
    pub hard_state: HardState,
    /// The snapshot, when one exists and passes its checksum.
    pub snapshot: Option<Snapshot>,
    /// Size of the snapshot file, when one exists.
    pub snapshot_file_bytes: Option<u64>,
    /// Why the snapshot file was rejected. [`Storage::open`] refuses to start in this case.
    pub snapshot_error: Option<String>,
    /// Every entry the log replays to, in index order, including any that Raft would
    /// discard on startup.
    pub entries: Vec<Entry>,
    /// How many leading entries of `entries` form the log Raft would start from: the
    /// contiguous run directly after the snapshot.
    pub usable_entries: usize,
}

impl Inspection {
    pub fn snapshot_index(&self) -> Index {
        self.snapshot.as_ref().map_or(0, |s| s.last_index)
    }

    /// The log a node would start from, after dropping entries covered by the snapshot
    /// or stranded behind a gap.
    pub fn usable(&self) -> &[Entry] {
        let skip = self
            .entries
            .iter()
            .take_while(|e| e.index <= self.snapshot_index())
            .count();
        &self.entries[skip..skip + self.usable_entries]
    }

    /// Entries the node would discard on startup.
    pub fn discarded_entries(&self) -> usize {
        self.entries.len() - self.usable_entries
    }

    /// Highest index a node would start with.
    pub fn last_index(&self) -> Index {
        self.snapshot_index() + self.usable_entries as u64
    }

    /// The commit index a node would start with, clamped the same way Raft clamps it.
    pub fn commit_index(&self) -> Index {
        self.hard_state
            .commit
            .clamp(self.snapshot_index(), self.last_index())
    }
}

/// Examines a storage directory without changing it.
///
/// Unlike [`Storage::open`], this never creates, truncates or rewrites anything, so it is
/// safe to run against the directory of a stopped node, or a copy of one, to see what the
/// node would recover. A corrupt snapshot is reported rather than treated as an error.
pub fn inspect(dir: impl AsRef<Path>) -> io::Result<Inspection> {
    let dir = dir.as_ref();
    let Some(bytes) = read_file(&dir.join("wal"))? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} holds no write-ahead log", dir.display()),
        ));
    };

    let (snapshot, snapshot_file_bytes, snapshot_error) = match read_file(&dir.join("snapshot"))? {
        None => (None, None, None),
        Some(raw) => {
            let size = Some(raw.len() as u64);
            match parse_snapshot(&raw) {
                Ok(snapshot) => (Some(snapshot), size, None),
                Err(e) => (None, size, Some(e.to_string())),
            }
        }
    };

    let mut recovered = Recovered::default();
    let mut records = RecordCounts::default();
    let valid = if bytes.len() < WAL_MAGIC.len() {
        0
    } else if &bytes[..WAL_MAGIC.len()] != WAL_MAGIC {
        return Err(invalid("write-ahead log has a bad magic number"));
    } else {
        replay(&bytes, &mut recovered, &mut records)
    };

    let snap_index = snapshot.as_ref().map_or(0, |s| s.last_index);
    // The same rule Raft applies on startup: keep the contiguous run after the snapshot.
    let usable_entries = (snap_index + 1..)
        .zip(recovered.entries.iter().filter(|e| e.index > snap_index))
        .take_while(|(expected, e)| e.index == *expected)
        .count();

    Ok(Inspection {
        wal_bytes: bytes.len() as u64,
        valid_bytes: valid as u64,
        torn_bytes: (bytes.len() - valid) as u64,
        records,
        hard_state: recovered.hard_state,
        snapshot,
        snapshot_file_bytes,
        snapshot_error,
        entries: recovered.entries,
        usable_entries,
    })
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
            let good = replay(&bytes, &mut recovered, &mut RecordCounts::default());
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
    fn inspection_reports_what_a_node_would_recover() {
        let dir = temp_dir("inspect");
        let (mut s, _) = Storage::open(&dir).unwrap();
        s.persist(&Ready {
            entries: vec![entry(1, 1, b"a"), entry(1, 2, b""), entry(1, 3, b"c")],
            hard_state: Some(HardState {
                term: 1,
                voted_for: Some(1),
                commit: 2,
            }),
            ..Ready::default()
        })
        .unwrap();
        s.persist(&Ready {
            truncate_from: Some(3),
            entries: vec![entry(2, 3, b"C"), entry(2, 4, b"d")],
            hard_state: Some(HardState {
                term: 2,
                voted_for: None,
                commit: 9,
            }),
            ..Ready::default()
        })
        .unwrap();
        let wal_len = s.wal_len().unwrap();
        drop(s);

        let report = inspect(&dir).unwrap();
        assert_eq!(report.wal_bytes, wal_len);
        assert_eq!(report.valid_bytes, wal_len);
        assert_eq!(report.torn_bytes, 0);
        assert_eq!(
            report.records,
            RecordCounts {
                hard_state: 2,
                truncate: 1,
                entry: 5
            }
        );
        assert!(report.snapshot.is_none() && report.snapshot_error.is_none());
        assert_eq!(report.usable_entries, 4);
        assert_eq!(report.last_index(), 4);
        // The stored commit index runs past the log, so it is clamped like Raft does.
        assert_eq!(report.hard_state.commit, 9);
        assert_eq!(report.commit_index(), 4);

        // The usable log is exactly what Raft itself starts from.
        let (_s, recovered) = Storage::open(&dir).unwrap();
        let raft = crate::core::Raft::new(crate::core::Config::new(1, vec![2, 3]), recovered);
        assert_eq!(report.usable(), raft.log());
        assert_eq!(report.commit_index(), raft.commit_index());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inspection_never_modifies_a_torn_log() {
        let dir = temp_dir("inspect-torn");
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
        drop(s);

        let wal = dir.join("wal");
        let full = fs::read(&wal).unwrap();
        for cut in good_len as usize..full.len() {
            fs::write(&wal, &full[..cut]).unwrap();
            let report = inspect(&dir).unwrap();
            assert_eq!(report.valid_bytes, good_len, "cut at {cut}");
            assert_eq!(report.torn_bytes, cut as u64 - good_len);
            assert_eq!(report.entries, vec![entry(1, 1, b"first")]);
            assert_eq!(
                fs::read(&wal).unwrap(),
                &full[..cut],
                "inspect changed the log"
            );
        }
        // Opening for real agrees with the report and repairs the tail.
        let (s, _) = Storage::open(&dir).unwrap();
        assert_eq!(s.wal_len().unwrap(), good_len);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inspection_discards_entries_covered_by_the_snapshot_or_behind_a_gap() {
        let dir = temp_dir("inspect-gap");
        let (mut s, _) = Storage::open(&dir).unwrap();
        let snapshot = Snapshot {
            last_index: 2,
            last_term: 1,
            data: b"state".to_vec(),
        };
        s.save_snapshot(&snapshot, &[], HardState::default())
            .unwrap();
        s.persist(&Ready {
            entries: vec![
                entry(1, 2, b"old"),
                entry(1, 3, b"c"),
                entry(1, 4, b"d"),
                entry(1, 6, b"stranded"),
            ],
            ..Ready::default()
        })
        .unwrap();
        drop(s);

        let report = inspect(&dir).unwrap();
        assert_eq!(report.snapshot, Some(snapshot));
        assert_eq!(report.snapshot_index(), 2);
        assert_eq!(report.usable_entries, 2);
        assert_eq!(report.discarded_entries(), 2);
        assert_eq!(report.usable(), &[entry(1, 3, b"c"), entry(1, 4, b"d")]);
        assert_eq!(report.last_index(), 4);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inspection_reports_a_corrupt_snapshot_instead_of_failing() {
        let dir = temp_dir("inspect-badsnap");
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
        bytes[10] ^= 1;
        fs::write(&path, &bytes).unwrap();

        let report = inspect(&dir).unwrap();
        assert!(report.snapshot.is_none());
        assert_eq!(report.snapshot_file_bytes, Some(bytes.len() as u64));
        assert!(report.snapshot_error.unwrap().contains("checksum"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inspection_of_a_missing_directory_creates_nothing() {
        let dir = temp_dir("inspect-missing");
        let err = inspect(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!dir.exists());
    }

    #[test]
    fn inspection_rejects_a_foreign_file() {
        let dir = temp_dir("inspect-foreign");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("wal"), b"NOTAWAL!rest").unwrap();
        assert_eq!(
            inspect(&dir).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
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
