mod diagnostics;
mod install_engine;
mod installer;
mod recovery;
mod repository;
mod setup;
mod status;
mod storage;
use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next();

    match command.as_deref() {
        Some("status") => status::run(),
        Some("pkg") => pkg_command(args.collect()),
        Some("search") => pkg_command(std::iter::once("search".to_string()).chain(args).collect()),
        Some("remove") => pkg_command(std::iter::once("remove".to_string()).chain(args).collect()),
        Some("update") => pkg_command(std::iter::once("update".to_string()).chain(args).collect()),
        Some("info") => pkg_command(std::iter::once("info".to_string()).chain(args).collect()),
        Some("list") => pkg_command(std::iter::once("list".to_string()).chain(args).collect()),
        Some("install") => {
            let rest: Vec<String> = args.collect();

            if rest.iter().any(|arg| {
                matches!(
                    arg.as_str(),
                    "--dry-run"
                        | "--preflight"
                        | "--execute"
                        | "--target"
                        | "--config"
                        | "--help"
                        | "-h"
                )
            }) {
                installer::run(rest)
            } else {
                pkg_command(std::iter::once("install".to_string()).chain(rest).collect())
            }
        }
        Some("setup") => setup::run(),
        Some("storage") => storage::run(),
        Some("diagnose") => diagnostics::run(),
        Some("recovery") => recovery::run(),
        Some("repo") => repository::run(args.collect()),
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
    println!("  veyra diagnose                 Диагностика системы");
    println!("  veyra recovery                 Проверка восстановления системы");
    println!("  veyra repo status              Состояние репозитория Veyra");
    println!("  veyra install --dry-run       Проверка плана установки");
    println!("  veyra search <слово>           Поиск программ");
    println!("  veyra install <пакет>          Установка пакета");
    println!("  veyra remove <пакет>           Удаление пакета");
    println!("  veyra update                   Обновление системы");
    println!("  veyra info <пакет>             Информация о пакете");
    println!("  veyra list                     Установленные пакеты");
    println!("  veyra pkg search <слово>       Поиск программ");
    println!("  veyra pkg install <пакет>      Установка программ");
    println!("  veyra pkg remove <пакет>       Удаление программы");
    println!("  veyra pkg update               Обновление системы");
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
    // Используется только при тестировании с отдельным pacman.conf.
    // В обычной работе берётся системная конфигурация pacman.
    let mut pacman_args = Vec::new();

    if let Some(config) = env::var_os("VEYRA_PACMAN_CONFIG") {
        pacman_args.push("--config".to_string());
        pacman_args.push(config.to_string_lossy().into_owned());
    }

    pacman_args.extend(args);

    if admin {
        let mut sudo_args = vec!["pacman".to_string()];
        sudo_args.extend(pacman_args);
        run("sudo", &sudo_args)
    } else {
        run("pacman", &pacman_args)
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
    println!("Veyra Package — пакетные команды через pacman");
    println!();
    println!("  veyra pkg search <слово>");
    println!("  veyra pkg install <пакет>");
    println!("  veyra pkg remove <пакет>");
    println!("  veyra pkg update");
    println!("  veyra pkg list");
    println!("  veyra pkg info <пакет>");
}
