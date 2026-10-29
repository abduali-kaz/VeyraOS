use crate::installer::{InstallPlan, check_target};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn run_command(program: &str, args: &[String]) -> Result<(), String> {
    println!("> {} {}", program, args.join(" "));

    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("Не удалось запустить {program}: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} завершился с ошибкой: {status}"))
    }
}

fn chroot(target: &Path, args: &[&str]) -> Result<(), String> {
    let mut command = vec![target.display().to_string()];
    command.extend(args.iter().map(|s| s.to_string()));
    run_command("arch-chroot", &command)
}

fn require_root() -> Result<(), String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| format!("Не удалось проверить права: {e}"))?;

    if String::from_utf8_lossy(&output.stdout).trim() != "0" {
        return Err("Для установки нужны права root. Запусти команду через sudo.".into());
    }

    Ok(())
}

fn check_empty_root(target: &Path) -> Result<(), String> {
    for entry in
        fs::read_dir(target).map_err(|e| format!("Не удалось прочитать целевой раздел: {e}"))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if name != "boot" && name != "lost+found" {
            return Err(format!(
                "Целевой раздел не пуст: найдено '{}'. Установка отменена.",
                name
            ));
        }

        if name == "boot" && !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            return Err("Каталог /boot должен быть каталогом.".into());
        }
    }

    if !target.join("boot").is_dir() {
        return Err("Не найден каталог целевой системы /boot.".into());
    }

    Ok(())
}

fn check_efi_partition(target: &Path) -> Result<PathBuf, String> {
    let boot = target
        .join("boot")
        .canonicalize()
        .map_err(|e| format!("Не удалось проверить каталог /boot: {e}"))?;

    let output = Command::new("findmnt")
        .args(["-n", "-o", "TARGET,FSTYPE", "--target"])
        .arg(&boot)
        .output()
        .map_err(|e| format!("Не удалось запустить findmnt: {e}"))?;

    if !output.status.success() {
        return Err("Не удалось проверить EFI-раздел.".into());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();

    if fields.len() != 2 {
        return Err("Не удалось определить точку монтирования EFI-раздела.".into());
    }

    let mounted = Path::new(fields[0])
        .canonicalize()
        .map_err(|e| format!("Не удалось проверить точку монтирования: {e}"))?;

    if mounted != boot {
        return Err("EFI-раздел должен быть отдельно смонтирован в целевой каталог /boot.".into());
    }

    if fields[1] != "vfat" {
        return Err(format!(
            "Для UEFI нужен EFI-раздел FAT32 (vfat), обнаружено: {}.",
            fields[1]
        ));
    }

    if fs::read_dir(&boot)
        .map_err(|e| e.to_string())?
        .next()
        .is_some()
    {
        return Err(
            "EFI-раздел не пуст. Для первой версии установщика нужен пустой EFI-раздел.".into(),
        );
    }

    Ok(boot)
}

fn write_file(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    fs::write(path, content).map_err(|e| format!("Не удалось записать {}: {e}", path.display()))?;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("Не удалось настроить права {}: {e}", path.display()))
}

fn configure_locale(target: &Path, locale: &str) -> Result<(), String> {
    let path = target.join("etc/locale.gen");
    let original =
        fs::read_to_string(&path).map_err(|e| format!("Не удалось прочитать locale.gen: {e}"))?;

    let wanted = format!("{locale} UTF-8");
    let mut found = false;
    let mut lines = Vec::new();

    for line in original.lines() {
        let trimmed = line.trim();
        let candidate = trimmed
            .strip_prefix('#')
            .map(str::trim_start)
            .unwrap_or(trimmed);

        if candidate == wanted {
            lines.push(wanted.clone());
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }

    if !found {
        return Err(format!("Локаль {wanted} отсутствует в /etc/locale.gen."));
    }

    fs::write(path, format!("{}\n", lines.join("\n")))
        .map_err(|e| format!("Не удалось обновить locale.gen: {e}"))
}

fn install(plan: &InstallPlan, target_arg: Option<&str>) -> Result<(), String> {
    require_root()?;

    if !Path::new("/sys/firmware/efi").is_dir() {
        return Err(
            "Первая версия установщика поддерживает только загрузку Live ISO через UEFI.".into(),
        );
    }

    let target_arg = target_arg.ok_or("Укажи целевой раздел: --target /mnt/veyra")?;

    if target_arg.contains(' ') {
        return Err("Путь целевого раздела не должен содержать пробелы.".into());
    }

    check_target(target_arg)?;

    let target = Path::new(target_arg)
        .canonicalize()
        .map_err(|e| format!("Не удалось определить целевой путь: {e}"))?;

    check_empty_root(&target)?;
    check_efi_partition(&target)?;

    let timezone = Path::new("/usr/share/zoneinfo").join(&plan.timezone);
    if !timezone.is_file() {
        return Err(format!("Не найден часовой пояс: {}", plan.timezone));
    }

    let veyra_binary = Path::new("/usr/local/bin/veyra");
    if !veyra_binary.is_file() {
        return Err("Не найден бинарный файл Veyra в Live-системе.".into());
    }

    let release_file = Path::new("/etc/veyra-os-release");
    if !release_file.is_file() {
        return Err("Не найден файл брендинга /etc/veyra-os-release.".into());
    }

    println!();
    println!("=== УСТАНОВКА VEYRA OS ===");
    println!("Целевой корень: {}", target.display());
    println!("EFI-раздел:     {}", target.join("boot").display());
    println!("Компьютер:      {}", plan.hostname);
    println!("Пользователь:   {}", plan.username);
    println!("Часовой пояс:   {}", plan.timezone);
    println!("Локаль:         {}", plan.locale);
    println!("Профиль:        {}", plan.profile);
    println!("Пакетов:        {}", plan.packages.len());
    println!();
    println!("Разделы не форматируются.");
    println!("Будут установлены пакеты, созданы файлы системы,");
    println!("настроен пользователь и установлен загрузчик GRUB.");
    println!();
    print!("Для продолжения введи INSTALL VEYRA: ");
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut confirmation = String::new();
    io::stdin()
        .read_line(&mut confirmation)
        .map_err(|e| e.to_string())?;

    if confirmation.trim() != "INSTALL VEYRA" {
        return Err("Подтверждение не совпало. Установка отменена.".into());
    }

    let mut pacstrap = Command::new("pacstrap");
    pacstrap
        .arg("-C")
        .arg("/etc/pacman.conf")
        .arg("-K")
        .arg(&target)
        .args(&plan.packages);

    let status = pacstrap
        .status()
        .map_err(|e| format!("Не удалось запустить pacstrap: {e}"))?;

    if !status.success() {
        return Err(format!(
            "Установка пакетов pacstrap завершилась с ошибкой: {status}"
        ));
    }

    let fstab = Command::new("genfstab")
        .arg("-U")
        .arg(&target)
        .output()
        .map_err(|e| format!("Не удалось запустить genfstab: {e}"))?;

    if !fstab.status.success() || fstab.stdout.is_empty() {
        return Err("Не удалось создать таблицу монтирования fstab.".into());
    }

    fs::write(target.join("etc/fstab"), fstab.stdout)
        .map_err(|e| format!("Не удалось записать fstab: {e}"))?;

    let etc = target.join("etc");
    fs::write(etc.join("hostname"), format!("{}\n", plan.hostname)).map_err(|e| e.to_string())?;

    fs::write(
        etc.join("hosts"),
        format!(
            "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 {}.localdomain {}\n",
            plan.hostname, plan.hostname
        ),
    )
    .map_err(|e| e.to_string())?;

    fs::write(etc.join("locale.conf"), format!("LANG={}\n", plan.locale))
        .map_err(|e| e.to_string())?;

    configure_locale(&target, &plan.locale)?;

    let localtime = etc.join("localtime");
    if fs::symlink_metadata(&localtime).is_ok() {
        fs::remove_file(&localtime).map_err(|e| e.to_string())?;
    }

    symlink(format!("/usr/share/zoneinfo/{}", plan.timezone), &localtime)
        .map_err(|e| format!("Не удалось настроить часовой пояс: {e}"))?;

    let os_release = etc.join("veyra-os-release");
    fs::copy(release_file, &os_release).map_err(|e| e.to_string())?;

    let current_release = etc.join("os-release");
    if fs::symlink_metadata(&current_release).is_ok() {
        fs::remove_file(&current_release).map_err(|e| e.to_string())?;
    }
    symlink("veyra-os-release", &current_release)
        .map_err(|e| format!("Не удалось настроить имя системы: {e}"))?;

    let bin_dir = target.join("usr/local/bin");
    fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;
    let target_binary = bin_dir.join("veyra");
    fs::copy(veyra_binary, &target_binary).map_err(|e| e.to_string())?;
    fs::set_permissions(&target_binary, fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;

    let sudoers = etc.join("sudoers.d");
    fs::create_dir_all(&sudoers).map_err(|e| e.to_string())?;
    write_file(
        &sudoers.join("10-veyra-wheel"),
        "%wheel ALL=(ALL:ALL) ALL\n",
        0o440,
    )?;

    chroot(
        &target,
        &[
            "useradd",
            "-m",
            "-G",
            "wheel",
            "-s",
            "/bin/bash",
            &plan.username,
        ],
    )?;

    println!();
    println!("Задай пароль пользователя {}.", plan.username);
    chroot(&target, &["passwd", &plan.username])?;
    chroot(&target, &["passwd", "-l", "root"])?;

    chroot(&target, &["locale-gen"])?;

    let target_string = target.display().to_string();
    run_command(
        "systemctl",
        &[
            "--root".into(),
            target_string.clone(),
            "enable".into(),
            "NetworkManager.service".into(),
            "sddm.service".into(),
        ],
    )?;

    chroot(
        &target,
        &[
            "grub-install",
            "--target=x86_64-efi",
            "--efi-directory=/boot",
            "--bootloader-id=Veyra",
            "--removable",
        ],
    )?;

    chroot(&target, &["grub-mkconfig", "-o", "/boot/grub/grub.cfg"])?;

    println!();
    println!("Установка Veyra OS завершена.");
    println!("Пользователь: {}", plan.username);
    println!("Система: {}", target.display());
    println!("Автоматической перезагрузки не будет.");
    println!("После проверки размонтируй целевые разделы и перезагрузи виртуальную машину.");

    Ok(())
}

pub(crate) fn execute(plan: &InstallPlan, target: Option<&str>) -> ExitCode {
    match install(plan, target) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Veyra Installer: {error}");
            ExitCode::FAILURE
        }
    }
}
