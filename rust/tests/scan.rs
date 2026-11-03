use dataset_delivery_audit::scan;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

fn root(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("delivery-audit-rust-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn empty_directory() {
    let path = root("empty");
    assert!(scan(&path).unwrap().is_empty());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn single_file_hash_and_size() {
    let path = root("single");
    fs::write(path.join("one.txt"), b"abc").unwrap();
    let values = scan(&path).unwrap();
    assert_eq!(values[0].size_bytes, 3);
    assert_eq!(values[0].sha256.as_deref(), Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn recursive_paths_are_posix_and_sorted() {
    let path = root("recursive");
    fs::create_dir_all(path.join("z/sub")).unwrap();
    fs::write(path.join("z/sub/b.txt"), b"b").unwrap();
    fs::write(path.join("a.txt"), b"a").unwrap();
    let paths: Vec<_> = scan(&path).unwrap().into_iter().map(|item| item.path).collect();
    assert_eq!(paths, vec!["a.txt", "z", "z/sub", "z/sub/b.txt"]);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn duplicate_hash_group_is_stable() {
    let path = root("duplicate");
    fs::write(path.join("a.txt"), b"same").unwrap();
    fs::write(path.join("b.txt"), b"same").unwrap();
    let values = scan(&path).unwrap();
    assert!(values[0].duplicate_content_group.is_some());
    assert_eq!(values[0].duplicate_content_group, values[1].duplicate_content_group);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn symlink_is_not_followed() {
    let path = root("symlink");
    fs::write(path.join("target.txt"), b"target").unwrap();
    symlink("target.txt", path.join("link.txt")).unwrap();
    let values = scan(&path).unwrap();
    let link = values.iter().find(|item| item.path == "link.txt").unwrap();
    assert_eq!(link.entry_type, "symlink");
    assert!(link.sha256.is_none());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn root_git_is_ignored_but_nested_git_is_visible() {
    let path = root("git");
    fs::create_dir_all(path.join(".git")).unwrap();
    fs::write(path.join(".git/config"), b"root").unwrap();
    fs::create_dir_all(path.join("child/.git")).unwrap();
    fs::write(path.join("child/.git/config"), b"nested").unwrap();
    let paths: Vec<_> = scan(&path).unwrap().into_iter().map(|item| item.path).collect();
    assert!(!paths.iter().any(|item| item == ".git" || item.starts_with(".git/")));
    assert!(paths.iter().any(|item| item == "child/.git/config"));
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn archive_and_encoding_detection() {
    let path = root("formats");
    fs::write(path.join("data.json"), b"{\"ok\":true}\n").unwrap();
    fs::write(path.join("bad.txt"), [0xff, 0xfe]).unwrap();
    let values = scan(&path).unwrap();
    assert_eq!(values[0].encoding_status, "invalid_utf8");
    assert_eq!(values[1].detected_format, "json");
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn missing_root_is_rejected() {
    let path = std::env::temp_dir().join(format!("delivery-audit-rust-{}-missing", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    assert_eq!(scan(&path).unwrap_err(), "input_root_not_directory");
}

