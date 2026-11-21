use super::{catalog::CATALOG, Library};
use crate::AppResult;
use console::{truncate_str, Term};
use dialoguer::{theme::ColorfulTheme, FuzzySelect};
use std::io::IsTerminal;

struct Choice {
    source: String,
    label: String,
    cached: bool,
}

struct CursorGuard<'a>(&'a Term);

impl Drop for CursorGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.show_cursor();
    }
}

impl Library {
    fn choices(&self) -> AppResult<Vec<Choice>> {
        let entries = self.entries()?;
        let available = |entry: &super::Entry| {
            std::fs::metadata(self.object(&entry.sha256))
                .is_ok_and(|metadata| metadata.is_file() && metadata.len() == entry.bytes)
        };
        let mut choices = Vec::new();
        for dictionary in CATALOG {
            let cached = entries
                .iter()
                .find(|entry| entry.id == dictionary.id)
                .is_some_and(&available);
            if self.offline && !cached {
                continue;
            }
            choices.push(Choice {
                source: format!("@{}", dictionary.id),
                label: format!(
                    "@{} [{}] {}",
                    dictionary.id,
                    if cached { "cached" } else { "stream" },
                    dictionary.description
                ),
                cached,
            });
        }
        for entry in entries
            .iter()
            .filter(|entry| !CATALOG.iter().any(|dictionary| dictionary.id == entry.id))
        {
            let cached = available(entry);
            let remote =
                entry.source.starts_with("https://") || entry.source.starts_with("http://");
            if !cached && (self.offline || !remote) {
                continue;
            }
            choices.push(Choice {
                source: format!("@{}", entry.id),
                label: format!(
                    "@{} [{}] {} lines · {}",
                    entry.id,
                    if cached { "cached" } else { "stream" },
                    entry.lines,
                    entry.source
                ),
                cached,
            });
        }
        choices.sort_by_key(|choice| !choice.cached);
        Ok(choices)
    }

    pub fn select(&self) -> AppResult<Option<String>> {
        let term = Term::stderr();
        if !std::io::stdin().is_terminal() || !term.is_term() {
            return Err("Wordlist selection requires an interactive terminal; pass -d '@ID', a file or a URL instead".into());
        }
        let choices = self.choices()?;
        if choices.is_empty() {
            return Err("No local wordlists available offline; import a file or fetch a dictionary online first".into());
        }
        let columns = usize::from(term.size().1).max(1);
        let hint = "  Search: type · Move: arrows/Tab · Select: Enter · Cancel: Esc";
        term.write_line(hint)?;
        let mut hint_rows = console::measure_text_width(hint).div_ceil(columns);
        if self.offline {
            let hint = "  Offline: cached/imported dictionaries only";
            term.write_line(hint)?;
            hint_rows += console::measure_text_width(hint).div_ceil(columns);
        }
        let width = usize::from(term.size().1).saturating_sub(6).max(20);
        let labels: Vec<_> = choices
            .iter()
            .enumerate()
            .map(|(index, choice)| {
                truncate_str(&format!("{}. {}", index + 1, choice.label), width, "…").into_owned()
            })
            .collect();
        let _cursor = CursorGuard(&term);
        let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Wordlist")
            .items(&labels)
            .default(0)
            .report(false)
            .max_length(10)
            .interact_on_opt(&term);
        term.clear_last_lines(hint_rows)?;
        let selection = selection?;
        Ok(selection.map(|index| choices[index].source.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picker_prioritizes_imported_copies_and_hides_unavailable_items_offline() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("words.txt");
        std::fs::write(&source, b"password\n").unwrap();
        let root = directory.path().join("cache");
        let online = Library::new(Some(&root), false).unwrap();
        online.import(&source, "personal").unwrap();
        assert_eq!(online.choices().unwrap()[0].source, "@personal");
        let offline = Library::new(Some(&root), true).unwrap();
        let choices = offline.choices().unwrap();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].source, "@personal");
        let entry = offline.load("personal").unwrap().unwrap();
        std::fs::remove_file(offline.object(&entry.sha256)).unwrap();
        assert!(offline.choices().unwrap().is_empty());
        assert!(source.exists());
    }
}
