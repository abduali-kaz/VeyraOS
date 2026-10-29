use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;

fn ask(label: &str, default: &str) -> Result<String, String> {
    print!("{label} [{default}]: ");
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|e| e.to_string())?;

    let value = value.trim();

    Ok(if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    })
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

fn packages_for(profile: &str) -> Vec<&'static str> {
    let mut packages = vec![
        "base",
        "linux",
        "linux-firmware",
        "grub",
        "efibootmgr",
        "sudo",
        "networkmanager",
        "plasma-desktop",
        "sddm",
        "konsole",
        "dolphin",
    ];

    match profile {
        "standard" => packages.extend([
            "firefox",
            "ark",
            "kate",
            "pipewire",
            "pipewire-alsa",
            "pipewire-pulse",
            "wireplumber",
            "flatpak",
        ]),
        "pro" => packages.extend([
            "firefox",
            "ark",
            "kate",
            "pipewire",
            "pipewire-alsa",
            "pipewire-pulse",
            "wireplumber",
            "flatpak",
            "git",
            "base-devel",
            "htop",
            "tmux",
        ]),
        _ => {}
    }

    packages
}

pub fn run() -> ExitCode {
    let args: Vec<String> = env::args().skip(2).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("Veyra Setup — мастер подготовки установки");
        println!("Запуск: veyra setup");
        println!("Результат: ~/.config/veyra/veyra-install.toml");
        return ExitCode::SUCCESS;
    }

    println!();
    println!("==================================");
    println!("        VEYRA SETUP");
    println!("==================================");
    println!("Подготовка конфигурации установки.");
    println!("Этот мастер не форматирует диски и не меняет текущую ОС.");
    println!("Пароли не запрашиваются и не сохраняются.");
    println!();

    let result = (|| -> Result<(), String> {
        let hostname = ask("Имя компьютера", "veyra")?;
        if !valid_hostname(&hostname) {
            return Err("Некорректное имя компьютера.".into());
        }

        let username = ask("Имя обычного пользователя", "veyra")?;
        if !valid_username(&username) {
            return Err("Имя пользователя должно начинаться с a-z или _, а далее содержать только a-z, цифры, _ и -.".into());
        }

        let timezone = ask("Часовой пояс", "Asia/Almaty")?;
        if !valid_timezone(&timezone) {
            return Err("Некорректный формат часового пояса.".into());
        }

        let locale = ask("Системная локаль", "en_US.UTF-8")?;
        if !valid_locale(&locale) {
            return Err("Некорректный формат локали.".into());
        }

        println!();
        println!("Профили: lite, standard, pro");
        let profile = ask("Профиль программ", "standard")?.to_ascii_lowercase();

        if !["lite", "standard", "pro"].contains(&profile.as_str()) {
            return Err("Выбери lite, standard или pro.".into());
        }

        let packages = packages_for(&profile);
        let quoted_packages = packages
            .iter()
            .map(|package| format!("\"{package}\""))
            .collect::<Vec<_>>()
            .join(", ");

        println!();
        println!("Проверь настройки:");
        println!("  Компьютер:  {hostname}");
        println!("  Пользователь: {username}");
        println!("  Часовой пояс: {timezone}");
        println!("  Локаль:      {locale}");
        println!("  Профиль:     {profile}");
        println!("  Пакетов в плане: {}", packages.len());
        println!();

        let confirm = ask("Сохранить план? (y/n)", "y")?;
        if !matches!(
            confirm.to_ascii_lowercase().as_str(),
            "y" | "yes" | "д" | "да"
        ) {
            println!("Сохранение отменено.");
            return Ok(());
        }

        let config_path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| "Не задана переменная HOME".to_string())?
            .join(".config/veyra/veyra-install.toml");
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let plan = format!(
            "# Veyra OS installation plan\n\
             # Пароли намеренно не хранятся в этом файле.\n\n\
             hostname = \"{hostname}\"\n\
             username = \"{username}\"\n\
             timezone = \"{timezone}\"\n\
             locale = \"{locale}\"\n\
             profile = \"{profile}\"\n\
             packages = [{quoted_packages}]\n"
        );

        fs::write(&config_path, plan).map_err(|e| format!("Не удалось сохранить план: {e}"))?;

        println!();
        println!("План сохранён: {}", config_path.display());
        println!(
            "План сохранён. Setup сохраняет план. Установщик экспериментальный — сначала проверь его в QEMU."
        );
        println!("Проверить план можно командой: veyra install --dry-run");
        Ok(())
    })();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Ошибка Veyra Setup: {error}");
            ExitCode::from(2)
        }
    }
}
