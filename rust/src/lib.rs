use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

pub const SCAN_VERSION: &str = "delivery-scan-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inventory {
    pub delivery_id: String,
    pub dataset_id: String,
    pub path: String,
    pub entry_type: String,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub extension: String,
    pub detected_format: String,
    pub encoding_status: String,
    pub empty: bool,
    pub archive: bool,
    pub duplicate_content_group: Option<String>,
    pub expectation_match: String,
    pub schema_version: String,
    pub algorithm_version: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn extension(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.ends_with(".tar.gz") {
        ".tar.gz".into()
    } else if lower.ends_with(".tgz") {
        ".tgz".into()
    } else {
        Path::new(&lower).extension().map(|value| format!(".{}", value.to_string_lossy())).unwrap_or_default()
    }
}

fn format(extension: &str, head: &[u8], encoding: &str) -> String {
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return "zip".into();
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return "gzip".into();
    }
    if head.len() >= 262 && &head[257..262] == b"ustar" {
        return "tar".into();
    }
    if encoding == "binary" {
        return "binary".into();
    }
    if encoding == "utf8" || encoding == "utf8_bom" {
        let start = if head.starts_with(&[0xef, 0xbb, 0xbf]) { 3 } else { 0 };
        let text = String::from_utf8_lossy(&head[start..]).trim_start().to_lowercase();
        if text.starts_with("<!doctype html") || text.starts_with("<html") {
            return "html".into();
        }
        if text.starts_with('{') || text.starts_with('[') {
            return if extension == ".jsonl" { "jsonl" } else { "json" }.into();
        }
        if text.lines().next().unwrap_or("").contains('\t') {
            return "tsv".into();
        }
    }
    match extension {
        ".json" => "json",
        ".jsonl" => "jsonl",
        ".tsv" => "tsv",
        ".html" | ".htm" => "html",
        ".zip" => "zip",
        ".tar" => "tar",
        ".tar.gz" | ".tgz" | ".gz" => "gzip",
        ".txt" => "text",
        _ => "unknown",
    }.into()
}

fn scan_file(path: &Path) -> Result<(u64, String, Vec<u8>, String), String> {
    let mut reader = BufReader::new(File::open(path).map_err(|error| error.to_string())?);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut head = Vec::new();
    let mut carry = Vec::new();
    let mut size = 0_u64;
    let mut binary = false;
    let mut invalid = false;
    loop {
        let count = reader.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 { break; }
        let chunk = &buffer[..count];
        digest.update(chunk);
        size += count as u64;
        if head.len() < 512 {
            head.extend_from_slice(&chunk[..chunk.len().min(512 - head.len())]);
        }
        binary |= chunk.contains(&0);
        if !invalid {
            carry.extend_from_slice(chunk);
            match std::str::from_utf8(&carry) {
                Ok(_) => carry.clear(),
                Err(error) if error.error_len().is_none() => {
                    let suffix = carry.split_off(error.valid_up_to());
                    carry = suffix;
                }
                Err(_) => invalid = true,
            }
        }
    }
    if !carry.is_empty() { invalid = true; }
    let archive = head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") || head.starts_with(&[0x1f, 0x8b]) || (head.len() >= 262 && &head[257..262] == b"ustar");
    let encoding = if archive { "not_applicable" } else if binary { "binary" } else if invalid { "invalid_utf8" } else if head.starts_with(&[0xef, 0xbb, 0xbf]) { "utf8_bom" } else { "utf8" };
    Ok((size, format!("sha256:{}", hex(&digest.finalize())), head, encoding.into()))
}

fn visit(root: &Path, directory: &Path, prefix: &str, output: &mut Vec<(PathBuf, String)>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(directory).map_err(|error| error.to_string())?.collect::<Result<_, _>>().map_err(|error| error.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name().into_string().map_err(|_| "non_utf8_path".to_string())?;
        let relative = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        if relative == ".git" { continue; }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        output.push((path.clone(), relative.clone()));
        if metadata.file_type().is_dir() {
            visit(root, &path, &relative, output)?;
        }
    }
    let _ = root;
    Ok(())
}

pub fn scan(root: &Path) -> Result<Vec<Inventory>, String> {
    if !root.is_dir() { return Err("input_root_not_directory".into()); }
    let mut paths = Vec::new();
    visit(root, root, "", &mut paths)?;
    let mut records = Vec::new();
    for (path, relative) in paths {
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        let ext = extension(&relative);
        let (entry_type, size, sha, detected, encoding): (String, u64, Option<String>, String, String) = if metadata.file_type().is_symlink() {
            ("symlink".into(), 0, None, "unknown".into(), "not_applicable".into())
        } else if metadata.file_type().is_dir() {
            ("directory".into(), 0, None, "unknown".into(), "not_applicable".into())
        } else if metadata.file_type().is_file() {
            let (size, sha, head, encoding) = scan_file(&path)?;
            let detected = format(&ext, &head, &encoding);
            ("regular_file".into(), size, Some(sha), detected, encoding)
        } else {
            return Err(format!("unsupported_filesystem_entry:{relative}"));
        };
        let archive = matches!(detected.as_str(), "zip" | "tar" | "gzip");
        records.push(Inventory {
            delivery_id: "__UNSPECIFIED__".into(), dataset_id: "__UNSPECIFIED__".into(), path: relative,
            entry_type: entry_type.clone(), size_bytes: size, sha256: sha, extension: ext,
            detected_format: detected, encoding_status: encoding,
            empty: entry_type == "regular_file" && size == 0, archive,
            duplicate_content_group: None, expectation_match: "not_evaluated".into(),
            schema_version: "file-inventory-v1".into(), algorithm_version: SCAN_VERSION.into(),
        });
    }
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if record.entry_type == "regular_file" {
            groups.entry(record.sha256.clone().unwrap()).or_default().push(index);
        }
    }
    for (sha, indexes) in groups {
        if indexes.len() > 1 {
            let group = format!("duplicate:{}", hex(&Sha256::digest(format!("{SCAN_VERSION}\x1f{sha}").as_bytes())));
            for index in indexes { records[index].duplicate_content_group = Some(group.clone()); }
        }
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(records)
}

pub fn write_jsonl(path: &Path, records: &[Inventory]) -> Result<(), String> {
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    for record in records {
        serde_json::to_writer(&mut file, record).map_err(|error| error.to_string())?;
        use std::io::Write;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
    }
    Ok(())
}
