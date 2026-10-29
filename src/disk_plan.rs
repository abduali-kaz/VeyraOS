use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const GIB: u64 = 1024 * 1024 * 1024;
const MIN_DISK_SIZE: u64 = 30 * GIB;
const EFI_SIZE: u64 = GIB;

struct DiskLayout {
    efi_bytes: u64,
    root_bytes: u64,
}

fn calculate_layout(size_bytes: u64) -> Result<DiskLayout, String> {
    if size_bytes < MIN_DISK_SIZE {
        return Err("Для плана установки нужен диск не менее 30 GiB.".into());
    }

    Ok(DiskLayout {
        efi_bytes: EFI_SIZE,
        root_bytes: size_bytes - EFI_SIZE,
    })
}

fn lsblk_field(field: &str, device: &Path, bytes: bool) -> Result<String, String> {
    let mut command = Command::new("lsblk");
    command.args(["--nodeps", "--noheadings", "--raw"]);

    if bytes {
        command.arg("--bytes");
    }

    let output = command
        .args(["--output", field])
        .arg(device)
        .output()
        .map_err(|error| format!("Не удалось запустить lsblk: {error}"))?;

    if !output.status.success() {
        return Err(format!("Не удалось прочитать поле lsblk: {field}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn has_partitions(types: &str) -> bool {
    types.lines().any(|line| line.trim() == "part")
}

fn has_signatures(output: &str) -> bool {
    !output.trim().is_empty()
}

fn inspect_disk(device: &str) -> Result<(PathBuf, u64, String), String> {
    let requested = Path::new(device);

    if !requested.is_absolute()
        || requested
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return Err("Укажи абсолютный путь к устройству, например /dev/vda.".into());
    }

    let canonical = requested
        .canonicalize()
        .map_err(|error| format!("Устройство недоступно: {error}"))?;

    if !canonical.starts_with("/dev") {
        return Err("Путь должен указывать на устройство в /dev.".into());
    }

    let kind = lsblk_field("TYPE", &canonical, false)?;
    if kind != "disk" {
        return Err(format!(
            "{} — не целый диск (тип: {}). Укажи устройство целиком, не раздел.",
            canonical.display(),
            kind
        ));
    }

    let read_only = lsblk_field("RO", &canonical, false)?;
    if read_only == "1" {
        return Err("Диск доступен только для чтения.".into());
    }

    // Консервативно разрешаем планировать только диск без разделов.
    let tree = Command::new("lsblk")
        .args(["--noheadings", "--list", "--output", "TYPE"])
        .arg(&canonical)
        .output()
        .map_err(|error| format!("Не удалось проверить разделы диска: {error}"))?;

    if !tree.status.success() {
        return Err("Не удалось проверить структуру диска.".into());
    }

    if has_partitions(&String::from_utf8_lossy(&tree.stdout)) {
        return Err("На диске уже есть разделы. Планирование для такой цели запрещено.".into());
    }

    // wipefs работает строго в режиме --no-act: только обнаружение сигнатур.
    let signatures = Command::new("wipefs")
        .args(["--no-act", "--noheadings", "--output", "TYPE"])
        .arg(&canonical)
        .output()
        .map_err(|error| format!("Не удалось проверить сигнатуры диска: {error}"))?;

    if !signatures.status.success() {
        return Err("Проверка сигнатур не прошла; планирование отменено.".into());
    }

    if has_signatures(&String::from_utf8_lossy(&signatures.stdout)) {
        return Err("Обнаружены существующие сигнатуры данных. Планирование запрещено.".into());
    }

    let mounts = Command::new("lsblk")
        .args([
            "--paths",
            "--raw",
            "--noheadings",
            "--output",
            "MOUNTPOINTS",
            "--tree",
        ])
        .arg(&canonical)
        .output()
        .map_err(|error| format!("Не удалось проверить точки монтирования: {error}"))?;

    if !mounts.status.success() {
        return Err("Не удалось проверить точки монтирования диска.".into());
    }

    if !String::from_utf8_lossy(&mounts.stdout).trim().is_empty() {
        return Err(
            "Диск или один из его разделов уже используется/смонтирован. Планирование запрещено."
                .into(),
        );
    }

    let size = lsblk_field("SIZE", &canonical, true)?
        .parse::<u64>()
        .map_err(|_| "Не удалось определить размер диска.".to_string())?;

    let model = lsblk_field("MODEL", &canonical, false)?;
    let model = if model.is_empty() {
        "модель не указана".to_string()
    } else {
        model
    };

    Ok((canonical, size, model))
}

fn format_gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB as f64)
}

pub fn run(device: &str) -> ExitCode {
    match inspect_disk(device).and_then(|(path, size, model)| {
        let layout = calculate_layout(size)?;
        println!("=== VEYRA INSTALLER: ПЛАН ДИСКА ===");
        println!("Режим: только чтение — диск не изменяется.");
        println!("Устройство: {}", path.display());
        println!("Модель:     {model}");
        println!("Размер:     {}", format_gib(size));
        println!();
        println!("Предлагаемая таблица разделов: GPT");
        println!("  Раздел 1: EFI System Partition");
        println!("    Размер:      {}", format_gib(layout.efi_bytes));
        println!("    Файловая система: FAT32 (vfat)");
        println!("    Точка монтирования: /boot");
        println!("  Раздел 2: корневая система");
        println!("    Размер:      около {}", format_gib(layout.root_bytes));
        println!("    Файловая система: ext4");
        println!("    Точка монтирования: /");
        println!("  Отдельный swap-раздел: не предусмотрен");
        println!();
        println!("Это предварительный план, а не разметка диска.");
        println!("Команды форматирования или изменения таблицы разделов не запускались.");
        Ok(())
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Veyra Disk Planner: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GIB, MIN_DISK_SIZE, calculate_layout, format_gib, has_partitions, has_signatures};

    #[test]
    fn forty_gib_disk_gets_efi_and_root_plan() {
        let layout = calculate_layout(40 * GIB).unwrap();
        assert_eq!(layout.efi_bytes, GIB);
        assert_eq!(layout.root_bytes, 39 * GIB);
    }

    #[test]
    fn disk_smaller_than_minimum_is_rejected() {
        assert!(calculate_layout(MIN_DISK_SIZE - 1).is_err());
    }

    #[test]
    fn minimum_size_is_accepted() {
        assert!(calculate_layout(MIN_DISK_SIZE).is_ok());
    }

    #[test]
    fn formats_disk_size_for_display() {
        assert_eq!(format_gib(40 * GIB), "40.0 GiB");
    }

    #[test]
    fn rejects_existing_partitions() {
        assert!(has_partitions("disk\npart\npart\n"));
        assert!(!has_partitions("disk\n"));
    }

    #[test]
    fn rejects_existing_signatures() {
        assert!(has_signatures("gpt\n"));
        assert!(!has_signatures(""));
        assert!(!has_signatures("  \n"));
    }
}
