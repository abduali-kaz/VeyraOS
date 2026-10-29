mod installer;
mod setup;
mod storage;
use std::env;
use std::fs;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next();

    match command.as_deref() {
        Some("status") => {
            show_status();
            ExitCode::SUCCESS
        }
        Some("pkg") => pkg_command(args.collect()),
        Some("setup") => setup::run(),
        Some("install") => installer::run(args.collect()),
        Some("storage") => storage::run(),
        Some("--version") | Some("-V") => {
            println!("Veyra Core {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            show_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("Неизвестная команда: {other}");
            show_help();
            ExitCode::from(2)
        }
    }
}

fn show_help() {
    println!("Veyra Core — системные инструменты Veyra OS");
    println!();
    println!("Команды:");
    println!("  veyra status                   Состояние системы");
    println!("  veyra setup                    Мастер настройки Veyra");
    println!("  veyra storage                  Просмотр дисков и разделов");
    println!("  veyra install --dry-run       Проверка плана установки");
    println!("  veyra pkg search <слово>       Поиск программ");
    println!("  veyra pkg install <пакет>      Установка программ");
    println!("  veyra pkg remove <пакет>       Удаление программы");
    println!("  veyra pkg update               Полное обновление Arch");
    println!("  veyra pkg list                 Список установленных пакетов");
    println!("  veyra pkg info <пакет>         Информация о пакете");
    println!("  veyra --version                Версия Veyra Core");
}

fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
}

fn run(program: &str, args: &[String]) -> ExitCode {
    match Command::new(program).args(args).status() {
        Ok(status) => {
            if status.success() {
                ExitCode::SUCCESS
            } else {
                eprintln!("Veyra: команда завершилась с ошибкой: {status}");
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("Veyra: не удалось запустить {program}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_pacman(admin: bool, args: Vec<String>) -> ExitCode {
    if admin {
        let mut sudo_args = vec!["pacman".to_string()];
        sudo_args.extend(args);
        run("sudo", &sudo_args)
    } else {
        run("pacman", &args)
    }
}

fn pkg_command(args: Vec<String>) -> ExitCode {
    let Some(action) = args.first().map(String::as_str) else {
        package_help();
        return ExitCode::SUCCESS;
    };

    match action {
        "help" | "--help" | "-h" => {
            package_help();
            ExitCode::SUCCESS
        }

        "search" => {
            if args.len() < 2 {
                eprintln!("Использование: veyra pkg search <слово>");
                return ExitCode::from(2);
            }

            let query = args[1..].join(" ");
            run_pacman(false, vec!["-Ss".into(), query])
        }

        "list" => {
            if args.len() != 1 {
                eprintln!("Использование: veyra pkg list");
                return ExitCode::from(2);
            }

            run_pacman(false, vec!["-Q".into()])
        }

        "info" => {
            if args.len() != 2 || !valid_package_name(&args[1]) {
                eprintln!("Использование: veyra pkg info <имя-пакета>");
                return ExitCode::from(2);
            }

            run_pacman(false, vec!["-Si".into(), args[1].clone()])
        }

        "install" | "remove" => {
            if args.len() < 2 || !args[1..].iter().all(|p| valid_package_name(p)) {
                eprintln!("Укажи корректное имя хотя бы одного пакета.");
                return ExitCode::from(2);
            }

            let mut pacman_args = if action == "install" {
                vec!["-S".to_string(), "--needed".to_string()]
            } else {
                // Обычное удаление: не удаляем зависимости автоматически.
                vec!["-R".to_string()]
            };

            pacman_args.extend(args[1..].iter().cloned());
            run_pacman(true, pacman_args)
        }

        "update" => {
            if args.len() != 1 {
                eprintln!("Использование: veyra pkg update");
                return ExitCode::from(2);
            }

            println!("Veyra: запускается полное обновление системы через pacman.");
            run_pacman(true, vec!["-Syu".to_string()])
        }

        _ => {
            eprintln!("Неизвестная операция пакетного менеджера: {action}");
            package_help();
            ExitCode::from(2)
        }
    }
}

fn package_help() {
    println!("Veyra Package — начальный интерфейс над pacman");
    println!();
    println!("  veyra pkg search <слово>");
    println!("  veyra pkg install <пакет>");
    println!("  veyra pkg remove <пакет>");
    println!("  veyra pkg update");
    println!("  veyra pkg list");
    println!("  veyra pkg info <пакет>");
}

fn output(program: &str, args: &[&str]) -> Option<String> {
    let result = Command::new(program).args(args).output().ok()?;

    if !result.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&result.stdout).trim().to_string())
}

fn os_name() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "Неизвестная Linux-система".to_string())
}

fn show_status() {
    println!();
    println!("==================================");
    println!("       VEYRA SYSTEM STATUS");
    println!("==================================");
    println!("Операционная система: {}", os_name());

    let hostname = fs::read_to_string("/etc/hostname")
        .map(|name| name.trim().to_string())
        .unwrap_or_else(|_| "неизвестно".to_string());
    println!("Имя компьютера:      {hostname}");

    println!(
        "Версия ядра:         {}",
        output("uname", &["-r"]).unwrap_or_else(|| "недоступна".into())
    );

    if let Ok(contents) = fs::read_to_string("/proc/uptime") {
        if let Some(seconds) = contents
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<f64>().ok())
        {
            let total = seconds as u64;
            println!(
                "Время работы:        {} д. {} ч. {} мин.",
                total / 86_400,
                (total % 86_400) / 3_600,
                (total % 3_600) / 60
            );
        }
    }

    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
        let get_kib = |key: &str| -> Option<u64> {
            contents.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;

                if name == key {
                    value.split_whitespace().next()?.parse().ok()
                } else {
                    None
                }
            })
        };

        if let (Some(total), Some(available)) = (get_kib("MemTotal"), get_kib("MemAvailable")) {
            let gib = 1024.0 * 1024.0;
            let used = total.saturating_sub(available);

            println!(
                "Оперативная память: {:.2} / {:.2} GiB",
                used as f64 / gib,
                total as f64 / gib
            );
        }
    }

    if let Ok(contents) = fs::read_to_string("/proc/loadavg") {
        let values: Vec<&str> = contents.split_whitespace().take(3).collect();

        if !values.is_empty() {
            println!("Средняя нагрузка:   {}", values.join(" "));
        }
    }

    println!("\nКорневой раздел:");

    match output("df", &["-h", "/"]) {
        Some(disk) => println!("{disk}"),
        None => println!("Не удалось получить информацию о диске."),
    }

    println!("==================================");
    println!("Диагностика Veyra: базовый режим\n");
}
