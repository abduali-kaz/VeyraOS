use std::path::Path;
use std::process::Command;

fn extract_partuuid(parameter: &str) -> Result<Option<&str>, &'static str> {
    let Some(value) = parameter.strip_prefix("PARTUUID=") else {
        return Ok(None);
    };

    if value.is_empty() {
        return Err("Параметр PARTUUID пуст.");
    }

    if value.contains('/') {
        return Err("PARTNROFF или другой суффикс PARTUUID пока не поддерживается.");
    }

    Ok(Some(value))
}

fn partuuids_equal(expected: &str, actual: &str) -> bool {
    expected.eq_ignore_ascii_case(actual)
}

fn parse_fstype_candidates(value: &str) -> Result<Vec<&str>, &'static str> {
    // Не удаляем пробелы автоматически: проверяем исходный формат.
    let candidates: Vec<&str> = value.split(',').collect();

    if candidates.is_empty()
        || candidates
            .iter()
            .any(|candidate| candidate.is_empty() || candidate.chars().any(char::is_whitespace))
    {
        return Err("Параметр rootfstype пуст или имеет некорректный формат.");
    }

    Ok(candidates)
}

fn filesystem_type_matches(expected: &str, actual: &str) -> Result<bool, &'static str> {
    let candidates = parse_fstype_candidates(expected)?;

    Ok(candidates
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(actual.trim())))
}

pub fn verify_root_parameter(target_root: &Path, parameter: &str) -> String {
    let expected = match extract_partuuid(parameter) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return format!(
                "[ИНФО] root={parameter} не использует PARTUUID; \
                 сравнение идентификаторов не выполнялось."
            );
        }
        Err(error) => {
            return format!("[ПРЕДУПРЕЖДЕНИЕ] {error}");
        }
    };

    let mount = match Command::new("findmnt")
        .args([
            "--noheadings",
            "--raw",
            "--output",
            "SOURCE",
            "--mountpoint",
        ])
        .arg(target_root)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return format!("[НЕ ПРОВЕРЕНО] Не удалось запустить findmnt: {error}");
        }
    };

    if !mount.status.success() {
        return format!(
            "[НЕ ПРОВЕРЕНО] Не удалось однозначно определить источник \
             точки монтирования {}.",
            target_root.display()
        );
    }

    let source = String::from_utf8_lossy(&mount.stdout).trim().to_string();

    if source.is_empty() || !source.starts_with("/dev/") {
        return format!(
            "[НЕ ПРОВЕРЕНО] Источник {} не является распознанным \
             блочным устройством: {source}",
            target_root.display()
        );
    }

    let result = match Command::new("blkid")
        .args(["-s", "PARTUUID", "-o", "value"])
        .arg(&source)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return format!("[НЕ ПРОВЕРЕНО] Не удалось запустить blkid: {error}");
        }
    };

    if !result.status.success() {
        return format!("[НЕ ПРОВЕРЕНО] Не удалось получить PARTUUID для {source}.");
    }

    let actual = String::from_utf8_lossy(&result.stdout).trim().to_string();

    if actual.is_empty() {
        return format!("[НЕ ПРОВЕРЕНО] У устройства {source} не удалось определить PARTUUID.");
    }

    if partuuids_equal(expected, &actual) {
        format!(
            "[СОВПАДЕНИЕ] PARTUUID из UKI соответствует текущему \
             корневому разделу {source}: {actual}"
        )
    } else {
        format!(
            "[НЕ СОВПАДАЕТ] UKI ожидает PARTUUID={expected}, \
             но у {source} идентификатор {actual}. \
             Автоматические исправления не выполнялись."
        )
    }
}

pub fn verify_root_fstype(target_root: &Path, expected: &str) -> String {
    if let Err(error) = parse_fstype_candidates(expected) {
        return format!("[ПРЕДУПРЕЖДЕНИЕ] {error}");
    }

    let result = match Command::new("findmnt")
        .args([
            "--noheadings",
            "--raw",
            "--output",
            "FSTYPE",
            "--mountpoint",
        ])
        .arg(target_root)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return format!("[НЕ ПРОВЕРЕНО] Не удалось запустить findmnt: {error}");
        }
    };

    if !result.status.success() {
        return format!(
            "[НЕ ПРОВЕРЕНО] Не удалось определить тип файловой системы \
             для {}.",
            target_root.display()
        );
    }

    let actual = String::from_utf8_lossy(&result.stdout).trim().to_string();

    if actual.is_empty() {
        return format!(
            "[НЕ ПРОВЕРЕНО] findmnt не сообщил тип файловой системы \
             для {}.",
            target_root.display()
        );
    }

    match filesystem_type_matches(expected, &actual) {
        Ok(true) => format!(
            "[СОВПАДЕНИЕ] rootfstype={expected} соответствует \
             фактическому типу файловой системы: {actual}."
        ),
        Ok(false) => format!(
            "[НЕ СОВПАДАЕТ] UKI указывает rootfstype={expected}, \
             а findmnt сообщает {actual}. Автоматические исправления \
             не выполнялись."
        ),
        Err(error) => format!("[ПРЕДУПРЕЖДЕНИЕ] {error}"),
    }
}

pub fn verify_root_parameters(
    target_root: &Path,
    root_parameter: &str,
    rootfstype: Option<&str>,
) -> String {
    let mut results = vec![verify_root_parameter(target_root, root_parameter)];

    if let Some(expected) = rootfstype {
        results.push(verify_root_fstype(target_root, expected));
    }

    results.join("\n")
}

#[cfg(test)]
mod tests {
    use super::{
        extract_partuuid, filesystem_type_matches, parse_fstype_candidates, partuuids_equal,
    };

    #[test]
    fn extracts_partuuid() {
        assert_eq!(extract_partuuid("PARTUUID=f7478e4b"), Ok(Some("f7478e4b")));
    }

    #[test]
    fn ignores_other_root_parameter_formats() {
        assert_eq!(extract_partuuid("UUID=abcd"), Ok(None));
        assert_eq!(extract_partuuid("/dev/sda2"), Ok(None));
    }

    #[test]
    fn rejects_empty_partuuid() {
        assert_eq!(
            extract_partuuid("PARTUUID="),
            Err("Параметр PARTUUID пуст.")
        );
    }

    #[test]
    fn rejects_partnroff_suffix() {
        assert_eq!(
            extract_partuuid("PARTUUID=abcd/PARTNROFF=1"),
            Err("PARTNROFF или другой суффикс PARTUUID пока не поддерживается.")
        );
    }

    #[test]
    fn compares_partuuid_case_insensitively() {
        assert!(partuuids_equal("F7478E4B", "f7478e4b"));
    }

    #[test]
    fn detects_different_partuuids() {
        assert!(!partuuids_equal("aaaa", "bbbb"));
    }

    #[test]
    fn matches_filesystem_case_insensitively() {
        assert!(filesystem_type_matches("ext4", "EXT4").unwrap());
    }

    #[test]
    fn matches_one_of_multiple_filesystem_types() {
        assert!(filesystem_type_matches("xfs,ext4", "ext4").unwrap());
        assert!(!filesystem_type_matches("xfs,btrfs", "ext4").unwrap());
    }

    #[test]
    fn rejects_empty_filesystem_candidates() {
        assert!(parse_fstype_candidates("").is_err());
        assert!(parse_fstype_candidates("ext4,").is_err());
        assert!(parse_fstype_candidates("ext4, xfs").is_err());
        assert!(parse_fstype_candidates(" ext4").is_err());
    }
}
