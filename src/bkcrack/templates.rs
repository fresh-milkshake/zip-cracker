#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    VerifiedCopy,
    FormatStructure,
    Variant,
}

#[derive(Clone, Debug)]
pub struct PlaintextGuess {
    pub description: String,
    pub bytes: Vec<u8>,
    pub extra: Vec<(u64, Vec<u8>)>,
    pub confidence: Confidence,
}

fn header(description: &str, bytes: Vec<u8>) -> PlaintextGuess {
    PlaintextGuess {
        description: description.into(),
        bytes,
        extra: Vec::new(),
        confidence: Confidence::Variant,
    }
}

pub fn for_entry(name: &str, size: u64) -> Vec<PlaintextGuess> {
    let extension = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let mut guesses = Vec::new();
    match extension.as_str() {
        "png" if size >= 57 => {
            let mut png = header(
                "PNG signature and IHDR chunk",
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec(),
            );
            png.extra
                .push((size - 12, b"\x00\x00\x00\x00IEND\xaeB\x60\x82".to_vec()));
            // PNG defines compression and filter method 0 independently of dimensions.
            png.extra.push((26, vec![0, 0]));
            png.confidence = Confidence::FormatStructure;
            guesses.push(png);
        }
        "wav" | "avi" | "webp" if size >= 12 && size - 8 <= u32::MAX as u64 => {
            let form = match extension.as_str() {
                "wav" => b"WAVE",
                "avi" => b"AVI ",
                _ => b"WEBP",
            };
            let mut bytes = b"RIFF".to_vec();
            bytes.extend_from_slice(&((size - 8) as u32).to_le_bytes());
            bytes.extend_from_slice(form);
            let mut riff = header("RIFF form and file size", bytes);
            riff.confidence = Confidence::FormatStructure;
            guesses.push(riff);
            if extension == "wav" && size >= 44 {
                for (channels, rate, bits) in [
                    (2u16, 44100u32, 16u16),
                    (2, 48000, 16),
                    (1, 44100, 16),
                    (1, 8000, 16),
                    (1, 16000, 16),
                    (2, 44100, 24),
                    (1, 8000, 8),
                ] {
                    let align = channels * bits / 8;
                    if (size - 44).rem_euclid(u64::from(align)) != 0 {
                        continue;
                    }
                    let mut bytes = b"RIFF".to_vec();
                    bytes.extend_from_slice(&((size - 8) as u32).to_le_bytes());
                    bytes.extend_from_slice(b"WAVEfmt \x10\x00\x00\x00\x01\x00");
                    bytes.extend_from_slice(&channels.to_le_bytes());
                    bytes.extend_from_slice(&rate.to_le_bytes());
                    bytes.extend_from_slice(&(rate * u32::from(align)).to_le_bytes());
                    bytes.extend_from_slice(&align.to_le_bytes());
                    bytes.extend_from_slice(&bits.to_le_bytes());
                    bytes.extend_from_slice(b"data");
                    bytes.extend_from_slice(&((size - 44) as u32).to_le_bytes());
                    guesses.push(header(&format!("WAV PCM, {channels} channels, {rate} Hz, {bits} bit, standard 44-byte header"), bytes));
                }
            }
        }
        "bmp" if size >= 54 && size <= u32::MAX as u64 => {
            for offset in [54u32, 122, 138, 1078] {
                if u64::from(offset) > size {
                    continue;
                }
                let mut bytes = b"BM".to_vec();
                bytes.extend_from_slice(&(size as u32).to_le_bytes());
                bytes.extend_from_slice(&[0; 4]);
                bytes.extend_from_slice(&offset.to_le_bytes());
                guesses.push(header(
                    &format!("BMP header, pixel offset {offset}, zero reserved fields"),
                    bytes,
                ));
            }
        }
        "pdf" if size >= 16 => {
            for version in ["1.7", "1.4", "1.5", "1.6", "2.0"] {
                for newline in ["\n", "\r\n"] {
                    let mut bytes = format!("%PDF-{version}{newline}%").into_bytes();
                    bytes.extend_from_slice(b"\xe2\xe3\xcf\xd3");
                    bytes.extend_from_slice(newline.as_bytes());
                    guesses.push(header(
                        &format!(
                            "PDF {version}, common binary comment, {}",
                            if newline == "\n" { "LF" } else { "CRLF" }
                        ),
                        bytes,
                    ));
                }
            }
        }
        "jpg" | "jpeg" if size >= 20 => {
            for (version, units, density) in [(1, 0, 1u16), (2, 0, 1), (1, 1, 72), (1, 1, 96)] {
                let mut bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01".to_vec();
                bytes.extend_from_slice(&[version, units]);
                bytes.extend_from_slice(&density.to_be_bytes());
                bytes.extend_from_slice(&density.to_be_bytes());
                bytes.extend_from_slice(&[0, 0]);
                guesses.push(header(
                    &format!(
                        "JPEG JFIF 1.{version:02}, units {units}, density {density}, no thumbnail"
                    ),
                    bytes,
                ));
            }
        }
        _ => {}
    }
    guesses.retain(|guess| guess.bytes.len() >= 12 && guess.bytes.len() as u64 <= size);
    guesses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_provides_contiguous_and_sparse_bytes() {
        let guesses = for_entry("path/IMAGE.PNG", 100);
        assert_eq!(guesses.len(), 1);
        assert_eq!(guesses[0].bytes.len(), 16);
        assert_eq!(guesses[0].extra[0].0, 88);
        assert_eq!(guesses[0].confidence, Confidence::FormatStructure);
    }

    #[test]
    fn riff_size_comes_from_entry_metadata() {
        let guesses = for_entry("audio.wav", 1234);
        assert_eq!(&guesses[0].bytes[..4], b"RIFF");
        assert_eq!(&guesses[0].bytes[4..8], &1226u32.to_le_bytes());
        assert_eq!(&guesses[0].bytes[8..], b"WAVE");
        assert!(for_entry("audio.wav", u64::MAX).is_empty());
    }

    #[test]
    fn short_signatures_and_unknown_text_do_not_become_attacks() {
        for name in ["file.gif", "file.txt", "file.bin"] {
            assert!(for_entry(name, 1000).is_empty());
        }
        assert!(for_entry("file.png", 7).is_empty());
    }

    #[test]
    fn predicted_png_bytes_match_real_png_without_open_copy() {
        use std::io::{Cursor, Read};
        let mut archive = zip::ZipArchive::new(Cursor::new(include_bytes!(
            "../../tests/fixtures/auto-png.bin"
        )))
        .unwrap();
        let mut plaintext = Vec::new();
        archive
            .by_index_decrypt(0, b"Unrelated-Test-Password!47")
            .unwrap()
            .read_to_end(&mut plaintext)
            .unwrap();
        let guess = for_entry("image.png", plaintext.len() as u64).remove(0);
        assert_eq!(guess.bytes, plaintext[..guess.bytes.len()]);
        for (offset, bytes) in guess.extra {
            assert_eq!(
                bytes,
                plaintext[offset as usize..offset as usize + bytes.len()]
            );
        }
    }

    #[test]
    fn pcm_wave_header_uses_consistent_lengths_and_rates() {
        let guesses = for_entry("audio.wav", 176444);
        let guess = guesses
            .iter()
            .find(|guess| guess.description.contains("2 channels, 44100 Hz, 16 bit"))
            .unwrap();
        assert_eq!(guess.bytes.len(), 44);
        assert_eq!(&guess.bytes[4..8], &176436u32.to_le_bytes());
        assert_eq!(&guess.bytes[28..32], &176400u32.to_le_bytes());
        assert_eq!(&guess.bytes[40..44], &176400u32.to_le_bytes());
        assert_eq!(guess.confidence, Confidence::Variant);
    }
}
