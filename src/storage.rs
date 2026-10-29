use std::path::Path;
use std::process::{Command, ExitCode};

fn show_mount(target: &str) {
    if !Path::new(target).exists() {
        println!("{target}: каталог отсутствует");
        return;
    }

    match Command::new("findmnt")
        .args(["-n", "-o", "SOURCE,TARGET,FSTYPE", "--target", target])
        .output()
    {
        Ok(output) if output.status.success() => {
            print!("{target}: {}", String::from_utf8_lossy(&output.stdout));
        }
        _ => println!("{target}: точку монтирования определить не удалось"),
    }
}

pub fn run() -> ExitCode {
    println!();
    println!("==================================");
    println!("       VEYRA STORAGE");
    println!("==================================");
    println!("Режим: только чтение. Диски не изменяются.");

    println!(
        "Текущий сеанс: {}",
        if Path::new("/sys/firmware/efi").is_dir() {
            "загрузка через UEFI"
        } else {
            "UEFI не обнаружен (возможен BIOS или ограниченная среда)"
        }
    );

    println!();
    println!("--- Диски и разделы ---");

    let result = Command::new("lsblk")
        .args([
            "-e7",
            "-o",
            "NAME,PATH,SIZE,TYPE,FSTYPE,FSAVAIL,FSUSE%,MOUNTPOINTS,MODEL",
        ])
        .status();

    match result {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!("lsblk завершился с ошибкой: {status}");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("Не удалось запустить lsblk: {error}");
            return ExitCode::FAILURE;
        }
    }

    println!();
    println!("--- Текущие точки монтирования ---");

    for target in ["/", "/boot", "/efi", "/mnt"] {
        show_mount(target);
    }

    println!();
    println!("Проверка завершена. Никаких изменений не выполнено.");
    println!();

    ExitCode::SUCCESS
}
