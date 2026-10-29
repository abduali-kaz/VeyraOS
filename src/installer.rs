use std::fs;
use std::path::{Component, Path};
use std::process::{Command, ExitCode};

pub(crate) struct InstallPlan {
    pub(crate) hostname: String,
    pub(crate) username: String,
    pub(crate) timezone: String,
    pub(crate) locale: String,
    pub(crate) profile: String,
    pub(crate) packages: Vec<String>,
}

fn read_field(text: &str, key: &str) -> Result<String, String> {
    for line in text.lines() {
        let line = line.trim();

        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };

        let rest = rest.trim_start();

        if !rest.starts_with('=') {
            continue;
        }

        let value = rest[1..].trim();

        return value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .map(str::to_string)
            .ok_or_else(|| format!("Поле {key} должно быть строкой в кавычках"));
    }

    Err(format!("Отсутствует поле {key}"))
}

fn valid_package(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
}

fn valid_username(value: &str) -> bool {
    let mut chars = value.bytes();

    matches!(chars.next(), Some(b'a'..=b'z' | b'_'))
        && value.len() <= 32
        && chars.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn valid_timezone(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'_' || b == b'-' || b == b'+')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn valid_locale(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-' || b == b'@')
}

fn read_packages(text: &str) -> Result<Vec<String>, String> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("packages"))
        .ok_or("Отсутствует список packages")?;

    let value = line
        .split_once('=')
        .ok_or("Некорректный список packages")?
        .1
        .trim();

    let inside = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .ok_or("Список пакетов должен быть заключён в []")?;

    let mut packages = Vec::new();

    for item in inside.split(',') {
        let item = item.trim();

        if item.is_empty() {
            continue;
        }

        let package = item
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or("Некорректное имя пакета")?;

        if !valid_package(package) {
            return Err(format!("Недопустимое имя пакета: {package}"));
        }

        if !packages.iter().any(|p| p == package) {
            packages.push(package.to_string());
        }
    }

    if packages.is_empty() {
        return Err("Список пакетов пуст".into());
    }

    Ok(packages)
}

fn load_plan(path: &str) -> Result<InstallPlan, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("Не удалось прочитать {path}: {e}"))?;

    let plan = InstallPlan {
        hostname: read_field(&text, "hostname")?,
        username: read_field(&text, "username")?,
        timezone: read_field(&text, "timezone")?,
        locale: read_field(&text, "locale")?,
        profile: read_field(&text, "profile")?,
        packages: read_packages(&text)?,
    };

    if !valid_hostname(&plan.hostname) {
        return Err("Некорректное имя компьютера".into());
    }

    if !valid_username(&plan.username) {
        return Err("Некорректное имя пользователя".into());
    }

    if !valid_timezone(&plan.timezone) {
        return Err("Некорректный часовой пояс".into());
    }

    if !valid_locale(&plan.locale) {
        return Err("Некорректная локаль".into());
    }

    if !["lite", "standard", "pro"].contains(&plan.profile.as_str()) {
        return Err("Неизвестный профиль установки".into());
    }

    for required in [
        "base",
        "linux",
        "linux-firmware",
        "grub",
        "efibootmgr",
        "sudo",
        "networkmanager",
        "plasma-desktop",
        "sddm",
    ] {
        if !plan.packages.iter().any(|p| p == required) {
            return Err(format!(
                "В плане отсутствует обязательный пакет: {required}"
            ));
        }
    }

    Ok(plan)
}

fn executable_exists(name: &str) -> bool {
    let Some(path_value) = std::env::var_os("PATH") else {
        return false;
    };

    std::env::split_paths(&path_value).any(|directory| {
        let path = directory.join(name);
        path.is_file()
    })
}

fn validate_target_location(canonical: &Path) -> Result<(), String> {
    if canonical.parent() != Some(Path::new("/mnt")) || canonical.file_name().is_none() {
        return Err(
            "Целевой раздел должен быть смонтирован непосредственно в /mnt/<имя>, например /mnt/veyra.".into()
        );
    }
    Ok(())
}

fn conflicting_mountpoint(mounts: &str, target_device: &str, target_mount: &str) -> Option<String> {
    let target_prefix = format!("{}/", target_mount.trim_end_matches('/'));

    mounts.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let device = fields.next()?;
        let mountpoint = fields.next()?;

        if device == target_device
            && mountpoint != target_mount
            && !mountpoint.starts_with(&target_prefix)
        {
            Some(mountpoint.to_string())
        } else {
            None
        }
    })
}

pub(crate) fn check_target(target: &str) -> Result<(), String> {
    let path = Path::new(target);

    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Err("Целевой путь должен быть абсолютным и не содержать '..'".into());
    }

    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Целевой путь недоступен: {e}"))?;

    if canonical == Path::new("/") {
        return Err("Запрещено выбирать корень текущей системы".into());
    }
    validate_target_location(&canonical)?;

    if !canonical.is_dir() {
        return Err("Целевой путь не является каталогом".into());
    }

    let result = Command::new("findmnt")
        .args(["-n", "-o", "TARGET", "--target"])
        .arg(&canonical)
        .output()
        .map_err(|e| format!("Не удалось запустить findmnt: {e}"))?;

    if !result.status.success() {
        return Err("Не удалось определить файловую систему целевого пути".into());
    }

    let mounted = String::from_utf8_lossy(&result.stdout).trim().to_string();

    let mounted = Path::new(&mounted)
        .canonicalize()
        .map_err(|e| format!("Не удалось проверить точку монтирования: {e}"))?;

    if mounted != canonical {
        return Err(format!(
            "{} не является отдельной точкой монтирования. \
             Установщик не будет использовать каталог текущей ОС.",
            canonical.display()
        ));
    }

    let target_device = Command::new("findmnt")
        .args(["-n", "-o", "MAJ:MIN", "--mountpoint"])
        .arg(&canonical)
        .output()
        .map_err(|e| format!("Не удалось определить целевой раздел: {e}"))?;

    if !target_device.status.success() {
        return Err("Не удалось определить устройство целевого раздела.".into());
    }

    let target_device = String::from_utf8_lossy(&target_device.stdout)
        .trim()
        .to_string();

    if target_device.is_empty() {
        return Err("Устройство целевого раздела не определено.".into());
    }

    let mounts = Command::new("findmnt")
        .args(["-rn", "-o", "MAJ:MIN,TARGET"])
        .output()
        .map_err(|e| format!("Не удалось проверить подключённые файловые системы: {e}"))?;

    if !mounts.status.success() {
        return Err("Не удалось проверить подключённые файловые системы.".into());
    }

    let mounts = String::from_utf8_lossy(&mounts.stdout);
    let target_mount = canonical.to_string_lossy();

    if let Some(existing) = conflicting_mountpoint(&mounts, &target_device, &target_mount) {
        return Err(format!(
            "Целевая файловая система уже используется в точке '{}'. Установка запрещена.",
            existing
        ));
    }

    println!("Целевой раздел смонтирован: {}", canonical.display());
    Ok(())
}

fn print_help() {
    println!("Veyra Installer");
    println!();
    println!("  veyra install --list-disks");
    println!("  veyra install --plan-disk /dev/vda");
    println!("  veyra install --dry-run");
    println!("  veyra install --preflight");
    println!("  veyra install --preflight --target /mnt/veyra");
    println!("  sudo veyra install --execute --target /mnt/veyra");
    println!("  veyra install --dry-run --config ~/.config/veyra/veyra-install.toml");
    println!();
    println!("--execute устанавливает систему в заранее подготовленный раздел.");
    println!("Разделы не форматируются автоматически.");
    println!("Перед реальной установкой обязательно проверь целевые разделы.");
}

fn show_disks() -> ExitCode {
    println!("=== VEYRA INSTALLER: ДИСКИ ===");
    println!("Режим: только чтение. Изменений дисков не выполняется.");
    println!();

    let result = Command::new("lsblk")
        .args([
            "--paths",
            "--tree",
            "--output",
            "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL,RM,RO",
        ])
        .output();

    match result {
        Ok(output) if output.status.success() => {
            print!("{}", String::from_utf8_lossy(&output.stdout));
            println!();
            println!("Перед установкой внимательно проверь устройство и разделы.");
            println!("Эта команда ничего не форматирует и не изменяет.");
            ExitCode::SUCCESS
        }
        Ok(output) => {
            eprintln!(
                "Не удалось получить список дисков: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("Не удалось запустить lsblk: {error}");
            ExitCode::FAILURE
        }
    }
}

fn default_config_path() -> String {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    // При запуске через sudo сначала ищем конфигурацию исходного пользователя.
    if let Ok(user) = std::env::var("SUDO_USER")
        && let Ok(output) = Command::new("getent")
            .args(["passwd", user.as_str()])
            .output()
        && output.status.success()
    {
        let passwd = String::from_utf8_lossy(&output.stdout);
        if let Some(home) = passwd
            .lines()
            .next()
            .and_then(|line| line.split(':').nth(5))
        {
            candidates.push(Path::new(home).join(".config/veyra/veyra-install.toml"));
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(Path::new(&home).join(".config/veyra/veyra-install.toml"));
    }

    // Совместимость со старой конфигурацией проекта.
    candidates.push(Path::new("config/veyra-install.toml").to_path_buf());

    if let Some(existing) = candidates.iter().find(|path| path.is_file()) {
        return existing.display().to_string();
    }

    candidates
        .first()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "config/veyra-install.toml".to_string())
}

pub fn run(args: Vec<String>) -> ExitCode {
    let mut config = default_config_path();
    let mut target: Option<String> = None;
    let mut list_disks = false;
    let mut plan_disk: Option<String> = None;
    let mut dry_run = false;
    let mut preflight = false;
    let mut execute = false;

    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }

            "--list-disks" => list_disks = true,
            "--dry-run" => dry_run = true,
            "--preflight" => preflight = true,
            "--execute" => execute = true,

            "--config" | "--target" | "--plan-disk" => {
                let option = args[i].clone();
                i += 1;

                if i >= args.len() {
                    eprintln!("После {option} необходимо указать значение.");
                    return ExitCode::from(2);
                }

                if option == "--config" {
                    config = args[i].clone();
                } else if option == "--target" {
                    target = Some(args[i].clone());
                } else {
                    plan_disk = Some(args[i].clone());
                }
            }

            other => {
                eprintln!("Неизвестный аргумент: {other}");
                print_help();
                return ExitCode::from(2);
            }
        }

        i += 1;
    }

    if let Some(device) = plan_disk.as_deref() {
        if list_disks || dry_run || preflight || execute || target.is_some() {
            eprintln!("Используй --plan-disk отдельно от других режимов.");
            return ExitCode::from(2);
        }
        return crate::disk_plan::run(device);
    }

    if list_disks {
        if dry_run || preflight || execute || target.is_some() {
            eprintln!("Используй --list-disks отдельно от других режимов.");
            return ExitCode::from(2);
        }
        return show_disks();
    }

    if [dry_run, preflight, execute]
        .into_iter()
        .filter(|v| *v)
        .count()
        != 1
    {
        eprintln!("Выбери ровно один режим: --dry-run, --preflight или --execute.");
        return ExitCode::from(2);
    }

    let plan = match load_plan(&config) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("Ошибка плана установки: {error}");
            return ExitCode::from(2);
        }
    };

    if dry_run {
        println!();
        println!("=== VEYRA INSTALLER: DRY RUN ===");
        println!("Компьютер:   {}", plan.hostname);
        println!("Пользователь: {}", plan.username);
        println!("Профиль:     {}", plan.profile);
        println!("Часовой пояс: {}", plan.timezone);
        println!("Локаль:      {}", plan.locale);
        println!("Пакетов:     {}", plan.packages.len());

        for package in &plan.packages {
            println!("  - {package}");
        }

        println!();
        println!("Проверка завершена. Изменений в системе нет.");
        println!("Форматирование дисков и установка пока отключены.");

        return ExitCode::SUCCESS;
    }

    if execute {
        return crate::install_engine::execute(&plan, target.as_deref());
    }

    println!("=== VEYRA INSTALLER: PREFLIGHT ===");
    println!("План конфигурации проверен: {config}");

    let mut failed = false;

    for tool in ["pacstrap", "genfstab", "arch-chroot"] {
        if executable_exists(tool) {
            println!("[OK] Найден инструмент: {tool}");
        } else {
            println!("[ОТСУТСТВУЕТ] {tool}");
            failed = true;
        }
    }

    if let Some(target) = target.as_deref() {
        match check_target(target) {
            Ok(()) => println!("[OK] Проверка целевого раздела завершена"),
            Err(error) => {
                eprintln!("[ОШИБКА] {error}");
                failed = true;
            }
        }
    } else {
        println!("[ПРОПУЩЕНО] Целевой раздел ещё не выбран.");
    }

    if failed {
        eprintln!();
        eprintln!("Проверка не пройдена. Установка не запускалась.");
        return ExitCode::FAILURE;
    }

    println!();
    println!("Проверки пройдены.");
    println!("Preflight завершён; фактическая установка не выполнялась.");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod target_safety_tests {
    use super::{conflicting_mountpoint, validate_target_location};
    use std::path::Path;

    #[test]
    fn accepts_a_named_mount_under_mnt() {
        assert!(validate_target_location(Path::new("/mnt/veyra")).is_ok());
    }

    #[test]
    fn rejects_filesystem_used_elsewhere() {
        let mounts = "8:2 /\n8:4 /mnt/veyra\n8:4 /home\n8:5 /mnt/veyra/boot\n";
        assert_eq!(
            conflicting_mountpoint(mounts, "8:4", "/mnt/veyra").as_deref(),
            Some("/home")
        );
    }

    #[test]
    fn allows_target_and_its_separate_boot_mount() {
        let mounts = "8:4 /mnt/veyra\n8:5 /mnt/veyra/boot\n";
        assert_eq!(conflicting_mountpoint(mounts, "8:4", "/mnt/veyra"), None);
    }

    #[test]
    fn rejects_host_system_paths() {
        for path in ["/", "/home", "/boot", "/mnt", "/tmp/veyra"] {
            assert!(
                validate_target_location(Path::new(path)).is_err(),
                "Путь {path} должен быть отклонён"
            );
        }
    }
}
