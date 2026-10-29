use std::fs;
use std::path::{Component, Path};
use std::process::{Command, ExitCode};

struct InstallPlan {
    hostname: String,
    username: String,
    timezone: String,
    locale: String,
    profile: String,
    packages: Vec<String>,
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

    for required in ["base", "linux", "sudo", "networkmanager", "sddm"] {
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

fn check_target(target: &str) -> Result<(), String> {
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

    println!("Целевой раздел смонтирован: {}", canonical.display());
    Ok(())
}

fn print_help() {
    println!("Veyra Installer");
    println!();
    println!("  cargo run -- install --dry-run");
    println!("  cargo run -- install --preflight");
    println!("  cargo run -- install --preflight --target /mnt/veyra");
    println!("  cargo run -- install --dry-run --config config/veyra-install.toml");
    println!();
    println!("Реальная установка пока не реализована.");
}

pub fn run(args: Vec<String>) -> ExitCode {
    let mut config = "config/veyra-install.toml".to_string();
    let mut target: Option<String> = None;
    let mut dry_run = false;
    let mut preflight = false;

    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }

            "--dry-run" => dry_run = true,
            "--preflight" => preflight = true,

            "--config" | "--target" => {
                let option = args[i].clone();
                i += 1;

                if i >= args.len() {
                    eprintln!("После {option} необходимо указать значение.");
                    return ExitCode::from(2);
                }

                if option == "--config" {
                    config = args[i].clone();
                } else {
                    target = Some(args[i].clone());
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

    if dry_run == preflight {
        eprintln!("Выбери ровно один режим: --dry-run или --preflight.");
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
    println!("Реальный режим установки пока отключён.");

    ExitCode::SUCCESS
}
