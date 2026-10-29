use std::collections::HashSet;
use std::fs::{self, File, Metadata, OpenOptions, ReadDir};
use std::io::{self, Read, Seek, SeekFrom, Write as _};
use std::path::Path;
use std::process::{Command, ExitCode};

#[path = "uki_integrity.rs"]
mod uki_integrity;

#[path = "root_validation.rs"]
mod root_validation;

const MAX_TEXT_SECTION_SIZE: u64 = 64 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
struct FstabAnalysis {
    entries: usize,
    malformed: usize,
    duplicate_mountpoints: Vec<String>,
    conflicting_options: Vec<String>,
    invalid_mountpoints: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LoaderConfigAnalysis {
    timeout: Option<String>,
    default: Option<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct UkiOsRelease {
    id: Option<String>,
    version_id: Option<String>,
    pretty_name: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct KernelCmdlineAnalysis {
    parameter_count: usize,
    root: Option<String>,
    rootfstype: Option<String>,
    init: Option<String>,
    has_ro: bool,
    has_rw: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Default)]
struct ArtifactScan {
    found: Vec<(&'static str, String)>,
    inaccessible: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeSection {
    name: String,
    raw_offset: u64,
    raw_size: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct PeInspection {
    file_size: u64,
    sections: Vec<PeSection>,
    overlapping_sections: Vec<(String, String)>,
}

impl PeInspection {
    fn has_section(&self, name: &str) -> bool {
        self.sections.iter().any(|section| section.name == name)
    }
}

impl ArtifactScan {
    fn finish(&mut self) {
        self.found.sort_by(|left, right| left.1.cmp(&right.1));
        self.found.dedup_by(|left, right| left.1 == right.1);
        self.inaccessible.sort();
        self.inaccessible.dedup();
    }
}

fn parse_os_name(contents: &str) -> Option<String> {
    parse_os_release_value(contents, "PRETTY_NAME")
}

fn parse_os_release_value(contents: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");

    let raw = contents
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))?
        .trim();

    let value = if let Some(quoted) = raw.strip_prefix('"') {
        quoted.strip_suffix('"')?
    } else if let Some(quoted) = raw.strip_prefix('\'') {
        quoted.strip_suffix('\'')?
    } else {
        raw
    };

    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn parse_uki_osrel(contents: &str) -> UkiOsRelease {
    UkiOsRelease {
        id: parse_os_release_value(contents, "ID"),
        version_id: parse_os_release_value(contents, "VERSION_ID"),
        pretty_name: parse_os_name(contents),
    }
}

fn analyze_kernel_cmdline(contents: &str) -> KernelCmdlineAnalysis {
    let mut report = KernelCmdlineAnalysis {
        parameter_count: contents.split_whitespace().count(),
        ..KernelCmdlineAnalysis::default()
    };

    let mut root_count = 0usize;
    let mut rootfstype_count = 0usize;
    let mut init_count = 0usize;

    for token in contents.split_whitespace() {
        if token == "ro" {
            report.has_ro = true;
        } else if token == "rw" {
            report.has_rw = true;
        } else if let Some(value) = token.strip_prefix("root=") {
            root_count += 1;

            if value.is_empty() {
                report
                    .warnings
                    .push("Параметр root задан без значения.".into());
            } else if report.root.is_none() {
                report.root = Some(value.to_string());
            }
        } else if let Some(value) = token.strip_prefix("rootfstype=") {
            rootfstype_count += 1;

            if value.is_empty() {
                report
                    .warnings
                    .push("Параметр rootfstype задан без значения.".into());
            } else if report.rootfstype.is_none() {
                report.rootfstype = Some(value.to_string());
            }
        } else if let Some(value) = token.strip_prefix("init=") {
            init_count += 1;

            if value.is_empty() {
                report
                    .warnings
                    .push("Параметр init задан без значения.".into());
            } else if report.init.is_none() {
                report.init = Some(value.to_string());
            }
        }
    }

    if root_count > 1 {
        report
            .warnings
            .push("Параметр root указан несколько раз.".into());
    }

    if rootfstype_count > 1 {
        report
            .warnings
            .push("Параметр rootfstype указан несколько раз.".into());
    }

    if init_count > 1 {
        report
            .warnings
            .push("Параметр init указан несколько раз.".into());
    }

    if report.has_ro && report.has_rw {
        report
            .warnings
            .push("Обнаружены оба параметра: ro и rw.".into());
    }

    report
}

fn analyze_fstab(contents: &str) -> FstabAnalysis {
    let mut report = FstabAnalysis::default();
    let mut seen_mountpoints = HashSet::new();

    const CONFLICTS: [(&str, &str); 9] = [
        ("ro", "rw"),
        ("exec", "noexec"),
        ("suid", "nosuid"),
        ("dev", "nodev"),
        ("auto", "noauto"),
        ("sync", "async"),
        ("atime", "noatime"),
        ("diratime", "nodiratime"),
        ("relatime", "norelatime"),
    ];

    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() != 6
            || fields[4].parse::<u32>().is_err()
            || fields[5].parse::<u32>().is_err()
        {
            report.malformed += 1;
            continue;
        }

        report.entries += 1;

        let mountpoint = fields[1];
        let filesystem = fields[2];
        let options: HashSet<&str> = fields[3].split(',').collect();

        if filesystem != "swap" && !mountpoint.starts_with('/') {
            report
                .invalid_mountpoints
                .push(format!("{mountpoint} (строка {})", index + 1));
        }

        if mountpoint.starts_with('/')
            && !seen_mountpoints.insert(mountpoint)
            && !report
                .duplicate_mountpoints
                .iter()
                .any(|existing| existing == mountpoint)
        {
            report.duplicate_mountpoints.push(mountpoint.to_string());
        }

        for (left, right) in CONFLICTS {
            if options.contains(left) && options.contains(right) {
                report.conflicting_options.push(format!(
                    "{mountpoint}: одновременно указаны {left} и {right}"
                ));
            }
        }
    }

    report
}

fn analyze_loader_conf(contents: &str) -> LoaderConfigAnalysis {
    let mut report = LoaderConfigAnalysis::default();
    let mut seen_directives: HashSet<String> = HashSet::new();

    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.split_whitespace();

        let Some(key) = fields.next() else {
            continue;
        };

        if key != "timeout" && key != "default" {
            continue;
        }

        if !seen_directives.insert(key.to_string()) {
            report.warnings.push(format!(
                "Строка {}: директива {key} указана повторно.",
                index + 1
            ));
            continue;
        }

        let Some(value) = fields.next() else {
            report.warnings.push(format!(
                "Строка {}: у директивы {key} отсутствует значение.",
                index + 1
            ));
            continue;
        };

        if fields.next().is_some() {
            report.warnings.push(format!(
                "Строка {}: у директивы {key} должно быть одно значение.",
                index + 1
            ));
            continue;
        }

        match key {
            "timeout" => {
                if value == "menu-force" || value.parse::<u32>().is_ok() {
                    report.timeout = Some(value.to_string());
                } else {
                    report.warnings.push(format!(
                        "Строка {}: значение timeout не распознано: {value}.",
                        index + 1
                    ));
                }
            }
            "default" => {
                report.default = Some(value.to_string());
            }
            _ => {}
        }
    }

    report
}

fn glob_matches(pattern: &str, value: &str) -> Option<bool> {
    if pattern
        .chars()
        .any(|character| matches!(character, '[' | ']' | '\\'))
    {
        return None;
    }

    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();

    let mut current = vec![false; value.len() + 1];
    current[0] = true;

    for token in pattern {
        let mut next = vec![false; value.len() + 1];

        match token {
            '*' => {
                next[0] = current[0];

                for index in 1..=value.len() {
                    next[index] = current[index] || next[index - 1];
                }
            }
            '?' => {
                next[1..].copy_from_slice(&current[..value.len()]);
            }
            literal => {
                for index in 1..=value.len() {
                    next[index] = current[index - 1] && value[index - 1] == literal;
                }
            }
        }

        current = next;
    }

    Some(current[value.len()])
}

fn default_pattern_matches(pattern: &str, scan: &ArtifactScan) -> Option<bool> {
    if pattern
        .chars()
        .any(|character| matches!(character, '[' | ']' | '\\'))
    {
        return None;
    }

    for (kind, path) in &scan.found {
        if *kind != "Предполагаемый UKI" && *kind != "Запись systemd-boot" {
            continue;
        }

        let Some(filename) = Path::new(path).file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if glob_matches(pattern, filename) == Some(true) {
            return Some(true);
        }
    }

    Some(false)
}

fn read_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buffer: &mut [u8],
    file_size: u64,
) -> Result<(), String> {
    let length = u64::try_from(buffer.len())
        .map_err(|_| "Размер буфера чтения слишком велик.".to_string())?;

    let end = offset
        .checked_add(length)
        .ok_or("Переполнение при вычислении смещения PE.".to_string())?;

    if end > file_size {
        return Err("Структура PE выходит за границы файла.".into());
    }

    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| format!("Не удалось перейти к заголовку PE: {error}"))?;

    reader
        .read_exact(buffer)
        .map_err(|error| format!("Не удалось прочитать заголовок PE: {error}"))
}

fn inspect_uki_reader<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
) -> Result<PeInspection, String> {
    if file_size < 64 {
        return Err("Файл слишком мал для заголовка PE.".into());
    }

    let mut dos_header = [0u8; 64];
    read_at(reader, 0, &mut dos_header, file_size)?;

    if &dos_header[0..2] != b"MZ" {
        return Err("Нет сигнатуры MZ: файл не похож на PE.".into());
    }

    let pe_offset = u32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .map_err(|_| "Некорректное поле e_lfanew.".to_string())?,
    ) as u64;

    if pe_offset < 64 {
        return Err("Смещение PE указывает внутрь DOS-заголовка.".into());
    }

    let mut coff_header = [0u8; 24];
    read_at(reader, pe_offset, &mut coff_header, file_size)?;

    if &coff_header[0..4] != b"PE\0\0" {
        return Err("Сигнатура PE\\0\\0 не найдена.".into());
    }

    let section_count = u16::from_le_bytes([coff_header[6], coff_header[7]]) as u64;
    let optional_size = u16::from_le_bytes([coff_header[20], coff_header[21]]) as u64;

    if section_count == 0 {
        return Err("В PE нет таблицы секций.".into());
    }

    if section_count > 4096 {
        return Err("Слишком много секций PE для безопасной проверки.".into());
    }

    let optional_start = pe_offset
        .checked_add(24)
        .ok_or("Переполнение смещения Optional Header.".to_string())?;

    let mut magic_bytes = [0u8; 2];
    read_at(reader, optional_start, &mut magic_bytes, file_size)?;

    let magic = u16::from_le_bytes(magic_bytes);

    let minimum_optional_size = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return Err("Неизвестный формат Optional Header PE.".into()),
    };

    if optional_size < minimum_optional_size {
        return Err("Optional Header короче допустимого минимального размера.".into());
    }

    let section_table = optional_start
        .checked_add(optional_size)
        .ok_or("Переполнение смещения таблицы секций.".to_string())?;

    let section_table_size = section_count
        .checked_mul(40)
        .ok_or("Переполнение размера таблицы секций.".to_string())?;

    let section_table_end = section_table
        .checked_add(section_table_size)
        .ok_or("Переполнение конца таблицы секций.".to_string())?;

    if section_table_end > file_size {
        return Err("Таблица секций PE выходит за границы файла.".into());
    }

    let mut sections = Vec::new();
    let mut data_ranges: Vec<(u64, u64, String)> = Vec::new();

    for index in 0..section_count {
        let section_offset = section_table
            .checked_add(
                index
                    .checked_mul(40)
                    .ok_or("Переполнение смещения секции PE.".to_string())?,
            )
            .ok_or("Переполнение смещения секции PE.".to_string())?;

        let mut header = [0u8; 40];
        read_at(reader, section_offset, &mut header, file_size)?;

        let name_end = header[..8].iter().position(|byte| *byte == 0).unwrap_or(8);

        if name_end == 0 {
            return Err(format!("Секция PE №{} имеет пустое имя.", index + 1));
        }

        let name = std::str::from_utf8(&header[..name_end])
            .map_err(|_| format!("Имя секции PE №{} не является UTF-8.", index + 1))?
            .to_string();

        let raw_size = u32::from_le_bytes(
            header[16..20]
                .try_into()
                .map_err(|_| "Некорректный размер секции PE.".to_string())?,
        ) as u64;

        let raw_offset = u32::from_le_bytes(
            header[20..24]
                .try_into()
                .map_err(|_| "Некорректное смещение секции PE.".to_string())?,
        ) as u64;

        if raw_size > 0 {
            let raw_end = raw_offset
                .checked_add(raw_size)
                .ok_or("Переполнение границ данных секции PE.".to_string())?;

            if raw_offset < section_table_end {
                return Err(format!(
                    "Данные секции {name} пересекаются с заголовками PE."
                ));
            }

            if raw_end > file_size {
                return Err(format!("Данные секции {name} выходят за границы файла."));
            }

            data_ranges.push((raw_offset, raw_end, name.clone()));
        }

        sections.push(PeSection {
            name,
            raw_offset,
            raw_size,
        });
    }

    data_ranges.sort_by_key(|range| range.0);

    let mut overlapping_sections = Vec::new();

    for (index, left) in data_ranges.iter().enumerate() {
        for right in data_ranges.iter().skip(index + 1) {
            if right.0 >= left.1 {
                break;
            }

            overlapping_sections.push((left.2.clone(), right.2.clone()));
        }
    }

    overlapping_sections.sort();
    overlapping_sections.dedup();

    Ok(PeInspection {
        file_size,
        sections,
        overlapping_sections,
    })
}

fn inspect_uki_file(path: &Path) -> Result<PeInspection, String> {
    let mut file =
        File::open(path).map_err(|error| format!("Не удалось открыть UKI для чтения: {error}"))?;

    let file_size = file
        .metadata()
        .map_err(|error| format!("Не удалось получить размер UKI: {error}"))?
        .len();

    inspect_uki_reader(&mut file, file_size)
}

fn read_text_section(
    path: &Path,
    inspection: &PeInspection,
    name: &str,
) -> Result<Option<String>, String> {
    let Some(section) = inspection
        .sections
        .iter()
        .find(|section| section.name == name)
    else {
        return Ok(None);
    };

    if section.raw_size > MAX_TEXT_SECTION_SIZE {
        return Err(format!(
            "Секция {name} превышает ограничение {} байт.",
            MAX_TEXT_SECTION_SIZE
        ));
    }

    let size = usize::try_from(section.raw_size)
        .map_err(|_| format!("Размер секции {name} невозможно обработать."))?;

    let mut file =
        File::open(path).map_err(|error| format!("Не удалось повторно открыть UKI: {error}"))?;

    file.seek(SeekFrom::Start(section.raw_offset))
        .map_err(|error| format!("Не удалось прочитать смещение секции {name}: {error}"))?;

    let mut bytes = vec![0u8; size];

    file.read_exact(&mut bytes)
        .map_err(|error| format!("Не удалось прочитать секцию {name}: {error}"))?;

    let text = String::from_utf8(bytes)
        .map_err(|_| format!("Секция {name} не содержит корректный UTF-8-текст."))?;

    Ok(Some(text.trim_matches('\0').trim().to_string()))
}

fn inspect_uki_candidates(root: &Path, scan: &ArtifactScan) {
    println!();
    println!("--- СТРУКТУРА UKI (PE/COFF) ---");

    let candidates: Vec<&String> = scan
        .found
        .iter()
        .filter(|(kind, _)| *kind == "Предполагаемый UKI")
        .map(|(_, path)| path)
        .collect();

    if candidates.is_empty() {
        if scan.inaccessible.is_empty() {
            println!("Кандидаты UKI не найдены в проверяемых каталогах.");
        } else {
            println!("Проверить UKI не удалось: часть каталогов недоступна.");
        }

        return;
    }

    for relative in candidates {
        println!("Файл: {relative}");

        let filesystem_path = root.join(relative.trim_start_matches('/'));

        match uki_integrity::inspect(filesystem_path.as_path()) {
            Ok(report) => {
                println!("SHA-256 (отпечаток UKI): {}", report.sha256);
                match report.signature_table {
                    Ok(uki_integrity::SignatureTableStatus::Absent) => {
                        println!("[НЕ ОБНАРУЖЕНА] Таблица Authenticode-сертификатов не найдена.");
                    }
                    Ok(uki_integrity::SignatureTableStatus::Present {
                        size_bytes,
                        entries,
                    }) => {
                        println!(
                            "[НАЙДЕНА ТАБЛИЦА СЕРТИФИКАТОВ] Размер: {size_bytes} байт, записей: {entries}."
                        );
                        println!(
                            "Криптографическая подпись и доверие к сертификату не проверялись."
                        );
                    }
                    Err(error) => {
                        println!(
                            "[ПРЕДУПРЕЖДЕНИЕ] Таблицу сертификатов проверить не удалось: {error}"
                        );
                    }
                }
                println!(
                    "SHA-256 — отпечаток содержимого, не доказательство подлинности без доверенного эталона."
                );
            }
            Err(error) => println!("[ПРЕДУПРЕЖДЕНИЕ] Не удалось вычислить SHA-256: {error}"),
        }

        match inspect_uki_file(&filesystem_path) {
            Err(error) => {
                println!("[ПРЕДУПРЕЖДЕНИЕ] Структура файла не подтверждена: {error}");
            }
            Ok(inspection) => {
                println!("[OK] Базовые заголовки PE/COFF и границы секций проверены.");
                println!("Размер файла: {} байт", inspection.file_size);

                if inspection.overlapping_sections.is_empty() {
                    println!("[OK] Диапазоны данных секций не пересекаются.");
                } else {
                    for (left, right) in &inspection.overlapping_sections {
                        println!("[ПРЕДУПРЕЖДЕНИЕ] Данные секций пересекаются: {left} и {right}.");
                    }
                }

                if inspection.has_section(".linux") {
                    println!("[OK] Секция .linux найдена.");
                } else {
                    println!(
                        "[ПРЕДУПРЕЖДЕНИЕ] Секция .linux не найдена: \
                         файл не подтверждён как стандартный UKI."
                    );
                }

                let section_names: Vec<&str> = inspection
                    .sections
                    .iter()
                    .map(|section| section.name.as_str())
                    .collect();

                println!("Секции: {}", section_names.join(", "));

                println!();
                println!("--- МЕТАДАННЫЕ UKI (.osrel) ---");

                match read_text_section(&filesystem_path, &inspection, ".osrel") {
                    Ok(Some(contents)) => {
                        let metadata = parse_uki_osrel(&contents);

                        match metadata.pretty_name {
                            Some(value) => println!("ОС: {value}"),
                            None => println!("PRETTY_NAME в .osrel отсутствует."),
                        }

                        match metadata.id {
                            Some(value) => println!("ID: {value}"),
                            None => println!("ID в .osrel отсутствует."),
                        }

                        match metadata.version_id {
                            Some(value) => println!("VERSION_ID: {value}"),
                            None => println!("VERSION_ID в .osrel отсутствует."),
                        }
                    }
                    Ok(None) => {
                        println!("[НЕ НАЙДЕНО] Секция .osrel отсутствует.");
                    }
                    Err(error) => {
                        println!("[ПРЕДУПРЕЖДЕНИЕ] Не удалось разобрать .osrel: {error}");
                    }
                }

                println!();
                println!("--- ПАРАМЕТРЫ ЯДРА (.cmdline) ---");

                match read_text_section(&filesystem_path, &inspection, ".cmdline") {
                    Ok(Some(contents)) => {
                        let cmdline = analyze_kernel_cmdline(&contents);

                        if let Some(root_device) = cmdline.root.as_deref() {
                            println!("--- СВЕРКА КОРНЕВОГО РАЗДЕЛА ---");
                            println!(
                                "{}",
                                root_validation::verify_root_parameters(
                                    root,
                                    root_device,
                                    cmdline.rootfstype.as_deref()
                                )
                            );
                        }

                        println!("Количество параметров: {}", cmdline.parameter_count);

                        if let Some(root_device) = &cmdline.root {
                            println!("root: {root_device}");
                        } else {
                            println!("Параметр root отсутствует.");
                        }

                        if let Some(filesystem) = &cmdline.rootfstype {
                            println!("rootfstype: {filesystem}");
                        }

                        if cmdline.has_ro && cmdline.has_rw {
                            println!("Режим root: противоречивые ro и rw.");
                        } else if cmdline.has_ro {
                            println!("Режим root: ro (только чтение).");
                        } else if cmdline.has_rw {
                            println!("Режим root: rw (чтение и запись).");
                        } else {
                            println!("Параметры ro/rw явно не заданы.");
                        }

                        if let Some(init) = &cmdline.init {
                            println!("init: {init}");
                        }

                        for warning in &cmdline.warnings {
                            println!("[ПРЕДУПРЕЖДЕНИЕ] {warning}");
                        }
                    }
                    Ok(None) => {
                        println!(
                            "[НЕ НАЙДЕНО] Секция .cmdline отсутствует; \
                             параметры могут поступать из другого источника."
                        );
                    }
                    Err(error) => {
                        println!("[ПРЕДУПРЕЖДЕНИЕ] Не удалось разобрать .cmdline: {error}");
                    }
                }

                println!();
                println!(
                    "Проверена структура PE, но не цифровая подпись, \
                     хеши содержимого или возможность загрузки."
                );
            }
        }
    }
}

fn package_manager(root: &Path) -> &'static str {
    if root.join("var/lib/pacman/local").is_dir() {
        "pacman (Arch Linux и совместимые системы)"
    } else if root.join("var/lib/dpkg/status").is_file() {
        "dpkg (Debian и совместимые системы)"
    } else if root.join("var/lib/rpm").is_dir() || root.join("usr/lib/sysimage/rpm").is_dir() {
        "RPM (Fedora и совместимые системы)"
    } else {
        "не определён"
    }
}

fn display_path(root: &Path, path: &Path) -> String {
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();

    if relative.is_empty() {
        "/".to_string()
    } else {
        format!("/{relative}")
    }
}

fn checked_metadata(root: &Path, path: &Path, scan: &mut ArtifactScan) -> Option<Metadata> {
    match fs::metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            scan.inaccessible
                .push(format!("{}: {error}", display_path(root, path)));
            None
        }
    }
}

fn checked_read_dir(root: &Path, path: &Path, scan: &mut ArtifactScan) -> Option<ReadDir> {
    match fs::read_dir(path) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            scan.inaccessible
                .push(format!("{}: {error}", display_path(root, path)));
            None
        }
    }
}

fn is_efi_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("efi"))
}

fn efi_artifact_label(path: &Path) -> &'static str {
    let parent_is_linux = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("Linux"));

    if parent_is_linux {
        "Предполагаемый UKI"
    } else {
        "EFI-файл"
    }
}

fn record_file(root: &Path, path: &Path, label: &'static str, scan: &mut ArtifactScan) {
    if let Some(metadata) = checked_metadata(root, path, scan)
        && metadata.is_file()
    {
        scan.found.push((label, display_path(root, path)));
    }
}

fn bootloader_artifacts(root: &Path) -> ArtifactScan {
    let mut scan = ArtifactScan::default();

    let boot_accessible = match checked_read_dir(root, &root.join("boot"), &mut scan) {
        Some(entries) => {
            drop(entries);
            true
        }
        None => false,
    };

    if boot_accessible {
        let configs = [
            ("Конфигурация GRUB", "boot/grub/grub.cfg"),
            ("Конфигурация GRUB", "boot/grub2/grub.cfg"),
            ("Конфигурация systemd-boot", "boot/loader/loader.conf"),
        ];

        for (label, relative) in configs {
            record_file(root, &root.join(relative), label, &mut scan);
        }

        let entries_path = root.join("boot/loader/entries");

        if let Some(entries) = checked_read_dir(root, &entries_path, &mut scan) {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let path = entry.path();

                        let is_conf = path
                            .extension()
                            .and_then(|extension| extension.to_str())
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("conf"));

                        if is_conf {
                            record_file(root, &path, "Запись systemd-boot", &mut scan);
                        } else {
                            let _ = checked_metadata(root, &path, &mut scan);
                        }
                    }
                    Err(error) => scan
                        .inaccessible
                        .push(format!("{}: {error}", display_path(root, &entries_path))),
                }
            }
        }
    }

    let efi_directories = ["boot/EFI", "boot/efi/EFI", "efi/EFI"];

    for base in efi_directories {
        if base.starts_with("boot/") && !boot_accessible {
            continue;
        }

        let base_path = root.join(base);

        if let Some(children) = checked_read_dir(root, &base_path, &mut scan) {
            for child in children {
                let child = match child {
                    Ok(child) => child,
                    Err(error) => {
                        scan.inaccessible
                            .push(format!("{}: {error}", display_path(root, &base_path)));
                        continue;
                    }
                };

                let path = child.path();

                let Some(metadata) = checked_metadata(root, &path, &mut scan) else {
                    continue;
                };

                if metadata.is_file() {
                    if is_efi_file(&path) {
                        scan.found
                            .push((efi_artifact_label(&path), display_path(root, &path)));
                    }

                    continue;
                }

                if !metadata.is_dir() {
                    continue;
                }

                if let Some(files) = checked_read_dir(root, &path, &mut scan) {
                    for file in files {
                        let file = match file {
                            Ok(file) => file,
                            Err(error) => {
                                scan.inaccessible
                                    .push(format!("{}: {error}", display_path(root, &path)));
                                continue;
                            }
                        };

                        let efi_path = file.path();

                        let Some(efi_metadata) = checked_metadata(root, &efi_path, &mut scan)
                        else {
                            continue;
                        };

                        if efi_metadata.is_file() && is_efi_file(&efi_path) {
                            scan.found.push((
                                efi_artifact_label(&efi_path),
                                display_path(root, &efi_path),
                            ));
                        }
                    }
                }
            }
        }
    }

    scan.finish();
    scan
}

fn boot_kernel_artifacts(root: &Path) -> ArtifactScan {
    let mut scan = ArtifactScan::default();
    let boot_directory = root.join("boot");

    let Some(entries) = checked_read_dir(root, &boot_directory, &mut scan) else {
        scan.finish();
        return scan;
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                scan.inaccessible
                    .push(format!("{}: {error}", display_path(root, &boot_directory)));
                continue;
            }
        };

        let path = entry.path();

        let Some(metadata) = checked_metadata(root, &path, &mut scan) else {
            continue;
        };

        if !metadata.is_file() {
            continue;
        }

        let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        let filename = filename.to_ascii_lowercase();

        let kind = if ["vmlinuz", "vmlinux", "bzimage", "zimage", "image"]
            .iter()
            .any(|prefix| filename.starts_with(prefix))
        {
            Some("Ядро Linux")
        } else if filename.starts_with("initramfs") || filename.starts_with("initrd") {
            Some("Отдельный initramfs/initrd")
        } else {
            None
        };

        if let Some(kind) = kind {
            scan.found.push((kind, display_path(root, &path)));
        }
    }

    scan.finish();
    scan
}

fn print_access_warnings(scan: &ArtifactScan) {
    for path in &scan.inaccessible {
        println!("[НЕТ ДОСТУПА] {path}");
    }

    if !scan.inaccessible.is_empty() {
        println!(
            "Некоторые пути не удалось проверить. Для полной диагностики \
             требуются права чтения исследуемой системы."
        );
    }
}

fn inspect_loader_config(root: &Path, scan: &ArtifactScan) {
    println!();
    println!("--- КОНФИГУРАЦИЯ SYSTEMD-BOOT ---");

    let path = root.join("boot/loader/loader.conf");

    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("loader.conf не найден. Это не обязательно ошибка.");
            return;
        }
        Err(error) => {
            println!("[НЕТ ДОСТУПА] {}: {error}", display_path(root, &path));
            return;
        }
    };

    let config = analyze_loader_conf(&contents);

    match &config.timeout {
        Some(timeout) => println!("[OK] timeout: {timeout}"),
        None => println!("timeout явно не задан в loader.conf."),
    }

    for warning in &config.warnings {
        println!("[ПРЕДУПРЕЖДЕНИЕ] {warning}");
    }

    match config.default.as_deref() {
        None => {
            println!("default явно не задан в loader.conf.");
            println!(
                "Выбор по умолчанию может зависеть от EFI-переменных \
                 и механизма выбора записей systemd-boot."
            );
        }
        Some("@saved") => {
            println!("default использует @saved: выбор зависит от сохранённой EFI-переменной.");
        }
        Some(pattern) => match default_pattern_matches(pattern, scan) {
            Some(true) => {
                println!("[OK] default соответствует обнаруженной записи: {pattern}");
            }
            Some(false) if !scan.inaccessible.is_empty() => {
                println!(
                    "Не удалось подтвердить default={pattern}: часть загрузочных путей недоступна."
                );
            }
            Some(false) => {
                println!(
                    "[ПРЕДУПРЕЖДЕНИЕ] default={pattern} не соответствует \
                     обнаруженным UKI или записям .conf."
                );
            }
            None => {
                println!(
                    "Шаблон default={pattern} содержит конструкцию, \
                     которую текущая проверка не интерпретирует."
                );
            }
        },
    }
}

fn inspect_root(root_arg: &str) -> Result<(), String> {
    let requested = Path::new(root_arg);

    if !requested.is_absolute() {
        return Err("Укажи абсолютный путь, например /mnt/target.".into());
    }

    let root = requested
        .canonicalize()
        .map_err(|error| format!("Путь недоступен: {error}"))?;

    if !root.is_dir() {
        return Err("Целевой путь не является каталогом.".into());
    }

    let release = fs::read_to_string(root.join("etc/os-release"))
        .map_err(|error| format!("Не удалось прочитать etc/os-release: {error}"))?;

    let os = parse_os_name(&release).unwrap_or_else(|| "Название не указано в os-release".into());

    println!("========================================");
    println!("          VEYRA RESCUE ENGINE");
    println!("========================================");
    println!("Режим: только чтение.");
    println!("Файлы и разделы не изменяются.");
    println!();
    println!("Корень системы: {}", root.display());
    println!("Обнаруженная ОС: {os}");
    println!("Менеджер пакетов: {}", package_manager(&root));

    println!();
    println!("--- КОНФИГУРАЦИЯ МОНТИРОВАНИЯ ---");

    match fs::read_to_string(root.join("etc/fstab")) {
        Ok(contents) => {
            let report = analyze_fstab(&contents);

            println!("Записей с корректной структурой: {}", report.entries);
            println!("Некорректных строк: {}", report.malformed);

            for mountpoint in &report.duplicate_mountpoints {
                println!("[ПРЕДУПРЕЖДЕНИЕ] Повторяется точка монтирования: {mountpoint}");
            }

            for conflict in &report.conflicting_options {
                println!("[ПРЕДУПРЕЖДЕНИЕ] Противоречивые параметры: {conflict}");
            }

            for mountpoint in &report.invalid_mountpoints {
                println!(
                    "[ПРЕДУПРЕЖДЕНИЕ] Точка монтирования должна быть абсолютным путём: {mountpoint}"
                );
            }

            if report.malformed == 0
                && report.duplicate_mountpoints.is_empty()
                && report.conflicting_options.is_empty()
                && report.invalid_mountpoints.is_empty()
            {
                println!("Типовых структурных проблем не обнаружено.");
            }

            println!("Проверка fstab предварительная.");
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("[ПРЕДУПРЕЖДЕНИЕ] /etc/fstab отсутствует.");
        }
        Err(error) => {
            println!("[НЕТ ДОСТУПА] /etc/fstab: {error}");
        }
    }

    let bootloader = bootloader_artifacts(&root);

    println!();
    println!("--- ЗАГРУЗЧИК ---");

    print_access_warnings(&bootloader);

    if bootloader.found.is_empty() {
        if bootloader.inaccessible.is_empty() {
            println!("Файлы загрузчика не найдены в проверяемых местах.");
            println!("Это не является доказательством поломки.");
        } else {
            println!("Не удалось достоверно проверить все пути загрузчика.");
        }
    } else {
        for (name, relative) in &bootloader.found {
            println!("[НАЙДЕН ФАЙЛ] {name}: {relative}");
        }

        println!("Наличие файлов само по себе не гарантирует исправную загрузку.");
    }

    inspect_loader_config(&root, &bootloader);
    inspect_uki_candidates(&root, &bootloader);

    let has_uki = bootloader
        .found
        .iter()
        .any(|(name, _)| *name == "Предполагаемый UKI");

    println!();
    println!("--- ЯДРО И INITRAMFS ---");

    let boot_files = boot_kernel_artifacts(&root);
    print_access_warnings(&boot_files);

    let has_separate_initramfs = boot_files
        .found
        .iter()
        .any(|(name, _)| *name == "Отдельный initramfs/initrd");

    if boot_files.found.is_empty() {
        if boot_files.inaccessible.is_empty() {
            println!("Ядро и initramfs не найдены в верхнем каталоге /boot.");
            println!("Проверь, подключён ли отдельный раздел /boot.");
        } else {
            println!("Не удалось достоверно проверить файлы в /boot.");
        }
    } else {
        for (name, relative) in &boot_files.found {
            println!("[НАЙДЕН ФАЙЛ] {name}: {relative}");
        }

        println!("Наличие файлов не гарантирует, что они исправны или согласованы.");
    }

    if has_uki && !has_separate_initramfs {
        println!(
            "Обнаружен предполагаемый UKI. Он может содержать ядро \
             и initramfs внутри единого EFI-файла."
        );
    }

    println!();
    println!("--- СЛУЖБЫ ---");

    if root.join("etc/systemd/system").is_dir() || root.join("usr/lib/systemd/system").is_dir() {
        println!("[НАЙДЕНО] Каталоги конфигурации systemd.");
    } else {
        println!("[ПРЕДУПРЕЖДЕНИЕ] Каталоги systemd не найдены или недоступны.");
    }

    println!();
    println!("Диагностика завершена. Исправления не выполнялись.");
    println!("Результаты являются предварительными.");
    println!("========================================");

    Ok(())
}

fn save_report(root_arg: &str, output_arg: &str) -> Result<(), String> {
    let root = Path::new(root_arg)
        .canonicalize()
        .map_err(|error| format!("Корень системы недоступен: {error}"))?;

    let requested = Path::new(output_arg);

    if !requested.is_absolute() {
        return Err("Путь --output должен быть абсолютным.".into());
    }

    let filename = requested.file_name().ok_or("Укажи имя файла отчёта.")?;

    let parent = requested
        .parent()
        .ok_or("Не удалось определить каталог отчёта.")?
        .canonicalize()
        .map_err(|error| format!("Каталог отчёта недоступен: {error}"))?;

    let allowed = if root == Path::new("/") {
        parent.starts_with("/tmp") || parent.starts_with("/home")
    } else {
        !parent.starts_with(&root)
    };

    if !allowed {
        return Err(
            "Небезопасный путь: выбери каталог вне исследуемой системы, например /tmp.".into(),
        );
    }

    let executable = std::env::current_exe()
        .map_err(|error| format!("Не удалось определить исполняемый файл: {error}"))?;

    let captured = Command::new(executable)
        .args(["rescue", "inspect", "--root"])
        .arg(&root)
        .output()
        .map_err(|error| format!("Не удалось выполнить диагностику: {error}"))?;

    if !captured.status.success() {
        return Err(format!(
            "Диагностика завершилась с ошибкой: {}",
            String::from_utf8_lossy(&captured.stderr).trim()
        ));
    }

    let destination = parent.join(filename);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| {
            format!(
                "Не удалось создать {}. Существующие файлы не перезаписываются: {error}",
                destination.display()
            )
        })?;

    if let Err(error) = file.write_all(&captured.stdout) {
        drop(file);
        let _ = fs::remove_file(&destination);

        return Err(format!("Ошибка записи отчёта: {error}"));
    }

    print!("{}", String::from_utf8_lossy(&captured.stdout));
    println!("Отчёт сохранён: {}", destination.display());

    Ok(())
}

pub fn run(args: Vec<String>) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("Veyra Rescue — диагностика установленной Linux-системы");
        println!("  veyra rescue inspect --root /mnt/target");
        println!("  veyra rescue inspect --root /");
        println!("  veyra rescue inspect --root / --output /tmp/veyra-report.txt");
        println!("Режим только для чтения; автоматического ремонта нет.");

        return ExitCode::SUCCESS;
    }

    if args.first().map(String::as_str) != Some("inspect") {
        eprintln!("Использование: veyra rescue inspect --root /mnt/target");
        return ExitCode::from(2);
    }

    let mut root: Option<&str> = None;
    let mut output_path: Option<&str> = None;
    let mut index = 1;

    while index < args.len() {
        let option = args[index].as_str();

        if option == "--root" || option == "--output" {
            index += 1;

            if index >= args.len() {
                eprintln!("После {option} необходимо указать путь.");
                return ExitCode::from(2);
            }

            if option == "--root" {
                root = Some(&args[index]);
            } else {
                output_path = Some(&args[index]);
            }
        } else {
            eprintln!("Неизвестный аргумент: {}", args[index]);
            return ExitCode::from(2);
        }

        index += 1;
    }

    let Some(root) = root else {
        eprintln!("Необходимо указать --root /mnt/target.");
        return ExitCode::from(2);
    };

    if let Some(destination) = output_path {
        return match save_report(root, destination) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Veyra Rescue: {error}");
                ExitCode::FAILURE
            }
        };
    }

    match inspect_root(root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Veyra Rescue: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactScan, analyze_fstab, analyze_kernel_cmdline, analyze_loader_conf,
        boot_kernel_artifacts, bootloader_artifacts, default_pattern_matches, inspect_uki_reader,
        parse_os_name, parse_uki_osrel,
    };
    use std::io::Cursor;

    fn make_test_pe(sections: &[(&str, &[u8])]) -> Vec<u8> {
        const PE_OFFSET: usize = 0x80;
        const OPTIONAL_SIZE: usize = 0xF0;

        let table_start = PE_OFFSET + 24 + OPTIONAL_SIZE;
        let table_end = table_start + sections.len() * 40;
        let mut next_raw = (table_end + 0x1ff) & !0x1ff;
        let mut raw_offsets = Vec::new();

        for (_, data) in sections {
            if data.is_empty() {
                raw_offsets.push(0usize);
            } else {
                raw_offsets.push(next_raw);
                next_raw = (next_raw + data.len() + 0x1ff) & !0x1ff;
            }
        }

        let mut bytes = vec![0u8; next_raw.max(table_end)];

        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        bytes[PE_OFFSET + 4..PE_OFFSET + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[PE_OFFSET + 6..PE_OFFSET + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        bytes[PE_OFFSET + 20..PE_OFFSET + 22]
            .copy_from_slice(&(OPTIONAL_SIZE as u16).to_le_bytes());
        bytes[PE_OFFSET + 24..PE_OFFSET + 26].copy_from_slice(&0x20bu16.to_le_bytes());

        for ((name, data), raw_offset) in sections.iter().zip(raw_offsets.iter()) {
            assert!(name.len() <= 8);

            let index = raw_offsets
                .iter()
                .position(|offset| offset == raw_offset)
                .unwrap();

            let header_start = table_start + index * 40;
            bytes[header_start..header_start + name.len()].copy_from_slice(name.as_bytes());

            bytes[header_start + 16..header_start + 20]
                .copy_from_slice(&(data.len() as u32).to_le_bytes());
            bytes[header_start + 20..header_start + 24]
                .copy_from_slice(&(*raw_offset as u32).to_le_bytes());

            if !data.is_empty() {
                bytes[*raw_offset..*raw_offset + data.len()].copy_from_slice(data);
            }
        }

        bytes
    }

    #[test]
    fn parses_linux_distribution_name() {
        assert_eq!(
            parse_os_name("NAME=Arch\nPRETTY_NAME=\"Arch Linux\"\n"),
            Some("Arch Linux".to_string())
        );
    }

    #[test]
    fn rejects_missing_or_broken_name() {
        assert_eq!(parse_os_name("NAME=Arch\n"), None);
        assert_eq!(parse_os_name("PRETTY_NAME=\"Arch Linux\n"), None);
        assert_eq!(parse_os_name("PRETTY_NAME=\"\"\n"), None);
    }

    #[test]
    fn parses_uki_osrel_metadata() {
        let report =
            parse_uki_osrel("ID=arch\nVERSION_ID=2026.10\nPRETTY_NAME=\"Arch Linux Test\"\n");

        assert_eq!(report.id.as_deref(), Some("arch"));
        assert_eq!(report.version_id.as_deref(), Some("2026.10"));
        assert_eq!(report.pretty_name.as_deref(), Some("Arch Linux Test"));
    }

    #[test]
    fn counts_fstab_entries_and_ignores_comments() {
        let contents = concat!(
            "# comment\n",
            "\n",
            "UUID=abc / ext4 defaults 0 1\n",
            "/dev/sda1 /boot vfat defaults 0 2\n",
        );

        let report = analyze_fstab(contents);

        assert_eq!(report.entries, 2);
        assert_eq!(report.malformed, 0);
    }

    #[test]
    fn detects_incomplete_fstab_rows() {
        let contents = concat!(
            "/dev/sda1 / ext4 defaults 0 1\n",
            "incomplete row\n",
            "# comment\n",
        );

        let report = analyze_fstab(contents);

        assert_eq!(report.entries, 1);
        assert_eq!(report.malformed, 1);
    }

    #[test]
    fn detects_duplicate_mountpoints() {
        let contents = concat!(
            "/dev/sda1 /data ext4 defaults 0 2\n",
            "/dev/sdb1 /data xfs defaults 0 2\n",
        );

        let report = analyze_fstab(contents);

        assert_eq!(report.duplicate_mountpoints, vec!["/data".to_string()]);
    }

    #[test]
    fn detects_conflicting_mount_options() {
        let report = analyze_fstab("/dev/sda1 /data ext4 defaults,ro,rw 0 2\n");

        assert!(
            report
                .conflicting_options
                .iter()
                .any(|warning| warning.contains("ro") && warning.contains("rw"))
        );
    }

    #[test]
    fn rejects_non_numeric_dump_and_pass_fields() {
        let report = analyze_fstab("/dev/sda1 / ext4 defaults invalid 1\n");

        assert_eq!(report.entries, 0);
        assert_eq!(report.malformed, 1);
    }

    #[test]
    fn detects_relative_mountpoints() {
        let report = analyze_fstab("/dev/sda1 data ext4 defaults 0 2\n");

        assert_eq!(report.invalid_mountpoints.len(), 1);
        assert!(report.invalid_mountpoints[0].contains("data"));
    }

    #[test]
    fn parses_kernel_cmdline_root_and_filesystem() {
        let report = analyze_kernel_cmdline("root=PARTUUID=test-root rootfstype=ext4 rw quiet");

        assert_eq!(report.parameter_count, 4);
        assert_eq!(report.root.as_deref(), Some("PARTUUID=test-root"));
        assert_eq!(report.rootfstype.as_deref(), Some("ext4"));
        assert!(report.has_rw);
        assert!(!report.has_ro);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn detects_duplicate_and_conflicting_cmdline_parameters() {
        let report = analyze_kernel_cmdline("root=/dev/test root=/dev/other ro rw");

        assert!(report.has_ro);
        assert!(report.has_rw);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("root"))
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("ro и rw"))
        );
    }

    #[test]
    fn parses_loader_timeout_and_default() {
        let report = analyze_loader_conf("timeout 3\n# comment\ndefault arch-*.efi\n");

        assert_eq!(report.timeout.as_deref(), Some("3"));
        assert_eq!(report.default.as_deref(), Some("arch-*.efi"));
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn detects_invalid_loader_timeout() {
        let report = analyze_loader_conf("timeout forever\n");

        assert_eq!(report.timeout, None);
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn detects_duplicate_loader_directives() {
        let report = analyze_loader_conf("timeout 3\ntimeout 5\n");

        assert_eq!(report.timeout.as_deref(), Some("3"));
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn matches_loader_default_against_uki() {
        let scan = ArtifactScan {
            found: vec![(
                "Предполагаемый UKI",
                "/boot/EFI/Linux/arch-linux.efi".to_string(),
            )],
            inaccessible: Vec::new(),
        };

        assert_eq!(default_pattern_matches("arch-*.efi", &scan), Some(true));

        assert_eq!(default_pattern_matches("missing.efi", &scan), Some(false));
    }

    #[test]
    fn parses_uki_pe_sections() {
        let linux = [1u8; 16];
        let initrd = [2u8; 16];
        let osrel = b"ID=arch\n";

        let bytes = make_test_pe(&[(".linux", &linux), (".initrd", &initrd), (".osrel", osrel)]);

        let file_size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);
        let report = inspect_uki_reader(&mut cursor, file_size).unwrap();

        assert!(report.has_section(".linux"));
        assert!(report.has_section(".initrd"));
        assert!(report.has_section(".osrel"));
        assert!(!report.has_section(".cmdline"));
        assert!(report.overlapping_sections.is_empty());
    }

    #[test]
    fn rejects_non_pe_uki_file() {
        let bytes = b"this is not a PE image";
        let mut cursor = Cursor::new(bytes.as_slice());

        assert!(inspect_uki_reader(&mut cursor, bytes.len() as u64).is_err());
    }

    #[test]
    fn rejects_out_of_bounds_pe_section() {
        let linux = [1u8; 16];
        let mut bytes = make_test_pe(&[(".linux", &linux)]);

        let table_start = 0x80 + 24 + 0xF0;
        bytes[table_start + 16..table_start + 20].copy_from_slice(&u32::MAX.to_le_bytes());

        let file_size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);

        assert!(inspect_uki_reader(&mut cursor, file_size).is_err());
    }

    #[test]
    fn detects_overlapping_section_ranges() {
        let linux = [1u8; 16];
        let initrd = [2u8; 16];

        let mut bytes = make_test_pe(&[(".linux", &linux), (".initrd", &initrd)]);
        let table_start = 0x80 + 24 + 0xF0;

        let first_offset = u32::from_le_bytes(
            bytes[table_start + 20..table_start + 24]
                .try_into()
                .unwrap(),
        );

        bytes[table_start + 40 + 20..table_start + 40 + 24]
            .copy_from_slice(&first_offset.to_le_bytes());

        let file_size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);
        let report = inspect_uki_reader(&mut cursor, file_size).unwrap();

        assert!(
            report
                .overlapping_sections
                .contains(&(".linux".to_string(), ".initrd".to_string()))
        );
    }

    #[test]
    fn does_not_assume_every_pe_contains_linux() {
        let initrd = [2u8; 16];
        let bytes = make_test_pe(&[(".initrd", &initrd)]);

        let file_size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);
        let report = inspect_uki_reader(&mut cursor, file_size).unwrap();

        assert!(!report.has_section(".linux"));
        assert!(report.has_section(".initrd"));
    }

    #[test]
    fn detects_grub2_configuration() {
        let root = std::env::temp_dir().join(format!("veyra-rescue-grub2-{}", std::process::id()));

        let _ = std::fs::remove_dir_all(&root);

        std::fs::create_dir_all(root.join("boot/grub2")).unwrap();
        std::fs::write(root.join("boot/grub2/grub.cfg"), "# test").unwrap();

        let found = bootloader_artifacts(&root);

        assert!(found.found.iter().any(|(name, path)| {
            *name == "Конфигурация GRUB" && path == "/boot/grub2/grub.cfg"
        }));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn detects_vendor_efi_file() {
        let root = std::env::temp_dir().join(format!("veyra-rescue-efi-{}", std::process::id()));

        let _ = std::fs::remove_dir_all(&root);

        let efi_dir = root.join("boot/efi/EFI/Veyra");
        std::fs::create_dir_all(&efi_dir).unwrap();
        std::fs::write(efi_dir.join("grubx64.efi"), "# test").unwrap();

        let found = bootloader_artifacts(&root);

        assert!(found.found.iter().any(|(name, path)| {
            *name == "EFI-файл" && path == "/boot/efi/EFI/Veyra/grubx64.efi"
        }));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn detects_uki_in_efi_linux_directory() {
        let root = std::env::temp_dir().join(format!("veyra-rescue-uki-{}", std::process::id()));

        let _ = std::fs::remove_dir_all(&root);

        let linux_dir = root.join("boot/EFI/Linux");
        std::fs::create_dir_all(&linux_dir).unwrap();
        std::fs::write(linux_dir.join("arch-linux.efi"), "# test").unwrap();

        let found = bootloader_artifacts(&root);

        assert!(found.found.iter().any(|(name, path)| {
            *name == "Предполагаемый UKI" && path == "/boot/EFI/Linux/arch-linux.efi"
        }));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn detects_linux_kernel() {
        let root = std::env::temp_dir().join(format!("veyra-rescue-kernel-{}", std::process::id()));

        let _ = std::fs::remove_dir_all(&root);

        std::fs::create_dir_all(root.join("boot")).unwrap();
        std::fs::write(root.join("boot/vmlinuz-linux"), "# test").unwrap();

        let found = boot_kernel_artifacts(&root);

        assert!(
            found
                .found
                .iter()
                .any(|(kind, path)| { *kind == "Ядро Linux" && path == "/boot/vmlinuz-linux" })
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn detects_initramfs() {
        let root =
            std::env::temp_dir().join(format!("veyra-rescue-initramfs-{}", std::process::id()));

        let _ = std::fs::remove_dir_all(&root);

        std::fs::create_dir_all(root.join("boot")).unwrap();
        std::fs::write(root.join("boot/initramfs-linux.img"), "# test").unwrap();

        let found = boot_kernel_artifacts(&root);

        assert!(found.found.iter().any(|(kind, path)| {
            *kind == "Отдельный initramfs/initrd" && path == "/boot/initramfs-linux.img"
        }));

        std::fs::remove_dir_all(&root).unwrap();
    }
}
