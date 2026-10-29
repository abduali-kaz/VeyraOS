use std::fs;
use std::process::{Command, ExitCode};

fn read_file(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn command_output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

            if output.status.success() {
                if stdout.is_empty() {
                    "Нет данных".into()
                } else {
                    stdout
                }
            } else if !stderr.is_empty() {
                format!("Команда вернула ошибку: {stderr}")
            } else if !stdout.is_empty() {
                stdout
            } else {
                format!("Команда завершилась с кодом {}", output.status)
            }
        }
        Err(error) => format!("Не удалось запустить {program}: {error}"),
    }
}

fn parse_pretty_name(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?.trim();
        let value = value.trim_matches('"').trim();

        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn parse_meminfo_kib(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;

        if name.trim() != key {
            return None;
        }

        value.split_whitespace().next()?.parse::<u64>().ok()
    })
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;

    if days > 0 {
        format!("{days} д. {hours} ч. {minutes} мин.")
    } else {
        format!("{hours} ч. {minutes} мин.")
    }
}

fn os_name() -> String {
    read_file("/etc/os-release")
        .and_then(|contents| parse_pretty_name(&contents))
        .unwrap_or_else(|| "Неизвестная Linux-система".into())
}

fn show_system() {
    println!("--- СИСТЕМА ---");
    println!("ОС:              {}", os_name());

    println!(
        "Имя компьютера:  {}",
        read_file("/etc/hostname")
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| "Недоступно".into())
    );

    println!("Ядро:            {}", command_output("uname", &["-r"]));
    println!("Архитектура:     {}", command_output("uname", &["-m"]));

    println!(
        "Режим загрузки:  {}",
        if std::path::Path::new("/sys/firmware/efi").is_dir() {
            "UEFI"
        } else {
            "BIOS или UEFI не обнаружен"
        }
    );

    if let Some(contents) = read_file("/proc/uptime") {
        if let Some(seconds) = contents
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<f64>().ok())
        {
            println!("Время работы:    {}", format_uptime(seconds as u64));
        }
    }
}

fn show_memory() {
    println!();
    println!("--- ПАМЯТЬ ---");

    if let Some(contents) = read_file("/proc/meminfo") {
        for (key, label) in [
            ("MemTotal", "Всего памяти"),
            ("MemAvailable", "Доступно памяти"),
            ("SwapTotal", "Всего swap"),
            ("SwapFree", "Свободно swap"),
        ] {
            if let Some(kib) = parse_meminfo_kib(&contents, key) {
                println!("{label}: {:.1} GiB", kib as f64 / 1_048_576.0);
            }
        }
    } else {
        println!("Информация о памяти недоступна.");
    }

    println!();
    println!("--- ПРОЦЕССОР ---");

    if let Some(contents) = read_file("/proc/cpuinfo") {
        if let Some(line) = contents.lines().find(|line| {
            line.starts_with("model name")
                || line.starts_with("Hardware")
                || line.starts_with("Processor")
        }) {
            println!("{}", line.replace('\t', " "));
        } else {
            println!("Модель процессора не определена.");
        }
    }
}

fn show_storage() {
    println!();
    println!("--- ДИСКИ И РАЗДЕЛЫ (ТОЛЬКО ЧТЕНИЕ) ---");
    println!(
        "{}",
        command_output(
            "lsblk",
            &["-e7", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS",],
        )
    );

    println!();
    println!("--- СВОБОДНОЕ МЕСТО ---");
    println!("{}", command_output("df", &["-h", "/", "/home", "/boot"]));
}

fn show_network() {
    println!();
    println!("--- СЕТЕВЫЕ ИНТЕРФЕЙСЫ ---");
    println!("{}", command_output("ip", &["-brief", "address"]));

    println!();
    println!("--- МАРШРУТЫ ---");
    println!("{}", command_output("ip", &["route"]));

    println!();
    println!("--- СЕТЕВЫЕ СЛУЖБЫ ---");

    for service in ["NetworkManager", "systemd-resolved"] {
        println!(
            "{service}: {}",
            command_output("systemctl", &["is-active", service])
        );
    }
}

fn show_services() {
    println!();
    println!("--- НЕИСПРАВНЫЕ СЛУЖБЫ ---");
    println!(
        "{}",
        command_output("systemctl", &["--failed", "--no-pager", "--no-legend"])
    );

    println!();
    println!("--- ОШИБКИ ТЕКУЩЕЙ ЗАГРУЗКИ ---");
    println!(
        "{}",
        command_output("journalctl", &["-b", "-p", "err", "--no-pager", "-n", "15"],)
    );
}

pub fn run() -> ExitCode {
    println!();
    println!("========================================");
    println!("       VEYRA DIAGNOSTICS");
    println!("========================================");
    println!("Режим: диагностика без изменения системы.");
    println!();

    show_system();
    show_memory();
    show_storage();
    show_network();
    show_services();

    println!();
    println!("Диагностика завершена. Система не изменялась.");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{format_uptime, parse_meminfo_kib, parse_pretty_name};

    #[test]
    fn reads_veyra_os_name() {
        let contents = "NAME=\"Veyra OS\"\nPRETTY_NAME=\"Veyra OS 2026\"\nID=veyra\n";
        assert_eq!(
            parse_pretty_name(contents).as_deref(),
            Some("Veyra OS 2026")
        );
    }

    #[test]
    fn rejects_missing_or_empty_os_name() {
        assert_eq!(parse_pretty_name("ID=veyra\n"), None);
        assert_eq!(parse_pretty_name("PRETTY_NAME=\"\"\n"), None);
    }

    #[test]
    fn parses_memory_values() {
        let contents =
            "MemTotal:       16000000 kB\nMemAvailable:    8000000 kB\nSwapTotal:       0 kB\n";
        assert_eq!(parse_meminfo_kib(contents, "MemTotal"), Some(16_000_000));
        assert_eq!(parse_meminfo_kib(contents, "MemAvailable"), Some(8_000_000));
        assert_eq!(parse_meminfo_kib(contents, "SwapTotal"), Some(0));
        assert_eq!(parse_meminfo_kib(contents, "Missing"), None);
    }

    #[test]
    fn formats_uptime() {
        assert_eq!(format_uptime(0), "0 ч. 0 мин.");
        assert_eq!(format_uptime(3_660), "1 ч. 1 мин.");
        assert_eq!(format_uptime(90_061), "1 д. 1 ч. 1 мин.");
    }
}
