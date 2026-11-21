use flate2::read::MultiGzDecoder;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

const MAX_LINE: u64 = 64 * 1024;

/// Preserve password bytes and spaces; only line endings and a UTF-8 BOM are removed.
pub struct Candidates {
    reader: BufReader<Box<dyn Read>>,
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
                64 * 1024,
                Box::new(io::Cursor::new(prefix).chain(input)),
            ),
        })
    }

    /// False means reading another line may block on network I/O.
    pub fn has_buffered_line(&self) -> bool {
        self.reader.buffer().contains(&b'\n')
    }

    pub fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        let read = self
            .reader
            .by_ref()
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(None);
        }
        if read as u64 > MAX_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Wordlist line exceeds 64 KiB; expected one password per line",
            ));
        }
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        Ok(Some(line))
    }
}

fn read_prefix(reader: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(3);
    reader.take(3).read_to_end(&mut bytes)?;
    Ok(bytes)
}
