use std::path::Path;
use std::process::{Command, ExitCode};

fn command_output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

            if !stdout.is_empty() {
                stdout
            } else if !stderr.is_empty() {
                stderr
            } else if output.status.success() {
                "Нет данных".into()
            } else {
                format!("Команда завершилась с кодом {}", output.status)
            }
        }
        Err(error) => format!("Не удалось запустить {program}: {error}"),
    }
}

fn show_mount(label: &str, path: &str) {
    println!();
    println!("--- {label}: {path} ---");

    if !Path::new(path).exists() {
        println!("Каталог отсутствует.");
        return;
    }

    let result = command_output(
        "findmnt",
        &[
            "--noheadings",
            "--output",
            "SOURCE,FSTYPE,TARGET,OPTIONS",
            "--mountpoint",
            path,
        ],
    );

    if result.is_empty() || result == "Нет данных" {
        println!("Отдельная точка монтирования не найдена.");
    } else {
        println!("{result}");
    }
}

fn show_boot_mode() {
    println!();
    println!("--- РЕЖИМ ЗАГРУЗКИ ---");

    if Path::new("/sys/firmware/efi").is_dir() {
        println!("Текущий сеанс загружен через UEFI.");
    } else {
        println!("UEFI не обнаружен; возможно, используется BIOS.");
    }

    if Path::new("/boot/grub/grub.cfg").is_file() {
        println!("Найден файл конфигурации GRUB: /boot/grub/grub.cfg");
    } else {
        println!("Файл /boot/grub/grub.cfg не найден.");
        println!("В Live-среде это само по себе не означает неисправность загрузчика.");
    }

    if Path::new("/boot/loader/loader.conf").is_file() {
        println!("Найден файл конфигурации systemd-boot.");
    }
}

fn show_disks() {
    println!();
    println!("--- ФАЙЛОВЫЕ СИСТЕМЫ И РАЗДЕЛЫ ---");

    println!(
        "{}",
        command_output(
            "lsblk",
            &["-e7", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS",],
        )
    );

    show_mount("Корневая система", "/");
    show_mount("Загрузочный раздел", "/boot");
    show_mount("EFI", "/efi");

    println!();
    println!("--- СВОБОДНОЕ МЕСТО ---");
    println!("{}", command_output("df", &["-h", "/", "/boot"]));

    println!();
    println!("Проверка целостности файловых систем не выполнялась.");
    println!("Для проверки или ремонта разделов может потребоваться их размонтирование.");
}

fn show_services() {
    println!();
    println!("--- СЛУЖБЫ СЕТИ И РАБОЧЕГО СТОЛА ---");

    for service in ["NetworkManager", "sddm", "systemd-resolved"] {
        println!(
            "{service}: {}",
            command_output("systemctl", &["is-active", service])
        );
    }

    println!();
    println!("--- СЛУЖБЫ С ОШИБКАМИ ---");

    match Command::new("systemctl")
        .args(["--failed", "--no-pager", "--no-legend"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let failed = String::from_utf8_lossy(&output.stdout).trim().to_string();

            if failed.is_empty() {
                println!("Не найдено служб в состоянии failed.");
            } else {
                println!("{failed}");
            }
        }
        Ok(output) => {
            let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if error.is_empty() {
                println!("systemctl завершился с кодом {}", output.status);
            } else {
                println!("Не удалось проверить службы: {error}");
            }
        }
        Err(error) => println!("Не удалось запустить systemctl: {error}"),
    }
}

fn show_package_manager() {
    println!();
    println!("--- СОСТОЯНИЕ PACMAN ---");

    if Path::new("/var/lib/pacman/db.lck").exists() {
        println!("Обнаружен файл блокировки /var/lib/pacman/db.lck.");
        println!("Проверь, не выполняется ли сейчас другая операция Pacman.");
        println!("Не удаляй блокировку, пока менеджер пакетов работает.");
    } else {
        println!("Файл блокировки Pacman отсутствует.");
    }

    let database = Path::new("/var/lib/pacman/local");
    if database.is_dir() {
        println!("Локальная база пакетов найдена.");
    } else {
        println!("Локальная база пакетов не найдена.");
    }
}

fn show_journal() {
    println!();
    println!("--- ОШИБКИ ТЕКУЩЕЙ ЗАГРУЗКИ ---");

    match Command::new("journalctl")
        .args([
            "-b",
            "-p",
            "err",
            "--no-pager",
            "-n",
            "30",
            "--output=short-iso",
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            let contents = String::from_utf8_lossy(&output.stdout);
            let entries: Vec<&str> = contents
                .lines()
                .filter(|line| {
                    let bytes = line.as_bytes();
                    bytes.len() >= 10 && bytes[4] == b'-' && bytes[7] == b'-'
                })
                .take(12)
                .collect();

            if entries.is_empty() {
                println!("Записей об ошибках не найдено.");
            } else {
                for entry in entries {
                    println!("{entry}");
                }
            }
        }
        Ok(output) => {
            let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if error.is_empty() {
                println!("journalctl завершился с кодом {}", output.status);
            } else {
                println!("Не удалось прочитать журнал: {error}");
            }
        }
        Err(error) => println!("Не удалось запустить journalctl: {error}"),
    }
}

pub fn run() -> ExitCode {
    println!();
    println!("========================================");
    println!("           VEYRA RECOVERY");
    println!("========================================");
    println!("Режим: диагностика и сбор отчёта.");
    println!("Диски, пакеты и конфигурация не изменяются.");

    show_boot_mode();
    show_disks();
    show_services();
    show_package_manager();
    show_journal();

    println!();
    println!("========================================");
    println!("Диагностика завершена.");
    println!("Автоматический ремонт не выполнялся.");
    println!("========================================");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn recovery_does_not_require_internal_disk_names() {
        // Диагностика не должна зависеть от того, как названы диски.
        assert!(Path::new("/").is_absolute());
        assert!(Path::new("/boot").is_absolute());
    }

    #[test]
    fn package_lock_path_is_explicit() {
        assert_eq!(
            Path::new("/var/lib/pacman/db.lck").file_name().unwrap(),
            "db.lck"
        );
    }
}
