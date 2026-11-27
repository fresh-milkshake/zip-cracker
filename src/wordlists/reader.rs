use flate2::read::MultiGzDecoder;
use memchr::memchr;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

const MAX_LINE: usize = 64 * 1024;

/// Preserve password bytes and spaces; only line endings and a UTF-8 BOM are removed.
pub struct Candidates {
    reader: BufReader<Box<dyn Read>>,
    line: Vec<u8>,
    consumed: usize,
}

impl Candidates {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::from_reader(File::open(path)?)
    }

    pub fn from_reader(input: impl Read + 'static) -> io::Result<Self> {
        let mut input: Box<dyn Read> = Box::new(input);
        let prefix = read_prefix(&mut input)?;
        let gzip = prefix.starts_with(&[0x1f, 0x8b]);
        let input = io::Cursor::new(prefix).chain(input);
        let mut input: Box<dyn Read> = if gzip {
            Box::new(MultiGzDecoder::new(input))
        } else {
            Box::new(input)
        };
        let mut prefix = read_prefix(&mut input)?;
        if prefix.starts_with(&[0xff, 0xfe]) || prefix.starts_with(&[0xfe, 0xff]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UTF-16 wordlist: convert it to UTF-8 first",
            ));
        }
        if prefix.starts_with(&[0xef, 0xbb, 0xbf]) {
            prefix.clear();
        }
        Ok(Self {
            reader: BufReader::with_capacity(
                MAX_LINE,
                Box::new(io::Cursor::new(prefix).chain(input)),
            ),
            line: Vec::new(),
            consumed: 0,
        })
    }

    /// False means reading another line may block on network I/O.
    pub fn has_buffered_line(&self) -> bool {
        memchr(b'\n', &self.reader.buffer()[self.consumed..]).is_some()
    }

    pub fn next(&mut self) -> io::Result<Option<&[u8]>> {
        self.reader.consume(std::mem::take(&mut self.consumed));
        let newline = loop {
            match self.reader.fill_buf() {
                Ok([]) => return Ok(None),
                Ok(buffered) => break memchr(b'\n', buffered),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        };
        if let Some(newline) = newline {
            // Leave the buffer in place until the next call so the caller can
            // use this line directly. The buffer capacity is also the line limit.
            self.consumed = newline + 1;
            return Ok(Some(trim_newline(&self.reader.buffer()[..self.consumed])));
        }
        self.line.clear();
        let read = self
            .reader
            .by_ref()
            .take((MAX_LINE + 1) as u64)
            .read_until(b'\n', &mut self.line)?;
        if read == 0 {
            return Ok(None);
        }
        if read > MAX_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Wordlist line exceeds 64 KiB; expected one password per line",
            ));
        }
        Ok(Some(trim_newline(&self.line)))
    }
}

fn trim_newline(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\n") {
        Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
        None => line,
    }
}

fn read_prefix(reader: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(3);
    reader.take(3).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_buffered_and_split_lines_without_losing_bytes() {
        // The prefix probe leaves "a\n" and one byte of the next candidate
        // in the initial read. The next candidate spans the input buffer.
        let mut bytes = b"a\n".to_vec();
        let long = vec![0xff; MAX_LINE - 2];
        bytes.extend_from_slice(&long);
        bytes.extend_from_slice(b"\r\n\n end\r");
        let mut candidates = Candidates::from_reader(io::Cursor::new(bytes)).unwrap();

        assert_eq!(candidates.next().unwrap(), Some(b"a".as_slice()));
        assert!(!candidates.has_buffered_line());
        assert_eq!(candidates.next().unwrap(), Some(long.as_slice()));
        assert!(candidates.has_buffered_line());
        assert_eq!(candidates.next().unwrap(), Some(b"".as_slice()));
        assert!(!candidates.has_buffered_line());
        assert_eq!(candidates.next().unwrap(), Some(b" end\r".as_slice()));
        assert_eq!(candidates.next().unwrap(), None);
    }
}
