use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

const REPO_NAME: &str = "veyra";
const REPO_URL: &str = "https://abduali-kaz.github.io/VeyraPackages/$arch";
const KEY_URL: &str = "https://abduali-kaz.github.io/VeyraPackages/keys/veyra-packages.asc";
const FINGERPRINT: &str = "A2DDB00AAC95FABBB80E5123B8CBBAB063D237A2";
const SYSTEM_CONFIG: &str = "/etc/pacman.conf";

fn config_path() -> PathBuf {
    env::var_os("VEYRA_PACMAN_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG))
}

fn section_info(text: &str) -> (bool, Option<String>, Option<String>) {
    let mut inside = false;
    let mut found = false;
    let mut server = None;
    let mut sig_level = None;

    for raw in text.lines() {
        let line = raw.trim();

        if line.starts_with('[') && line.ends_with(']') {
            inside = line == "[veyra]";
            if inside {
                found = true;
            }
            continue;
        }

        if !inside || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "Server" => server = Some(value.trim().to_string()),
                "SigLevel" => sig_level = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }

    (found, server, sig_level)
}

fn show_status() -> Result<(), String> {
    let path = config_path();
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("Не удалось прочитать {}: {e}", path.display()))?;

    println!("Veyra Repository");
    println!("Конфигурация: {}", path.display());

    let (found, server, sig_level) = section_info(&text);

    if !found {
        println!("Статус: не подключён");
        println!("Для просмотра плана: veyra repo enable --dry-run");
        return Ok(());
    }

    println!("Статус: секция [veyra] найдена");
    println!("Server: {}", server.as_deref().unwrap_or("(не задан)"));
    println!(
        "SigLevel: {}",
        sig_level.as_deref().unwrap_or("(по умолчанию)")
    );

    if server.as_deref() == Some(REPO_URL) && sig_level.as_deref() == Some("Required TrustedOnly") {
        println!("Проверка конфигурации: ожидаемый адрес и обязательные подписи заданы.");
    } else {
        println!("ВНИМАНИЕ: адрес или настройка подписей отличаются от ожидаемых.");
    }

    Ok(())
}

fn enable_dry_run() {
    println!("Veyra Repository — план подключения");
    println!();
    println!("Конфигурация: {SYSTEM_CONFIG}");
    println!("Открытый ключ: {KEY_URL}");
    println!("Отпечаток:     {FINGERPRINT}");
    println!();
    println!("Будут выполнены следующие действия:");
    println!("  1. Скачать открытый ключ по HTTPS.");
    println!("  2. Сверить полный отпечаток ключа.");
    println!("  3. Импортировать ключ через pacman-key.");
    println!("  4. Локально подписать ключ в системном keyring.");
    println!("  5. Сделать резервную копию pacman.conf.");
    println!("  6. Добавить [veyra] с SigLevel = Required TrustedOnly.");
    println!();
    println!("Режим dry-run: никаких изменений не выполнено.");
}

fn run_checked(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("Не удалось запустить {program}: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} завершился с кодом {status}"))
    }
}

fn download_and_verify_key(path: &PathBuf) -> Result<(), String> {
    let status = Command::new("curl")
        .args(["-fsSL", "--proto", "=https", "--tlsv1.2", KEY_URL, "-o"])
        .arg(path)
        .status()
        .map_err(|e| format!("Не удалось запустить curl: {e}"))?;

    if !status.success() {
        return Err("Не удалось скачать открытый ключ Veyra.".into());
    }

    let output = Command::new("gpg")
        .args(["--show-keys", "--with-colons", "--fingerprint"])
        .arg(path)
        .output()
        .map_err(|e| format!("Не удалось проверить GPG-ключ: {e}"))?;

    if !output.status.success() {
        return Err("Файл не распознан как корректный GPG-ключ.".into());
    }

    let fingerprint = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.first() == Some(&"fpr") {
                fields.get(9).map(|s| (*s).to_string())
            } else {
                None
            }
        })
        .ok_or("Не удалось прочитать отпечаток GPG-ключа")?;

    if !fingerprint.eq_ignore_ascii_case(FINGERPRINT) {
        return Err(format!(
            "Отпечаток ключа не совпадает. Получен: {fingerprint}"
        ));
    }

    println!("Открытый ключ проверен: отпечаток совпадает.");
    Ok(())
}

fn append_repository_section() -> Result<(), String> {
    let config = fs::read_to_string(SYSTEM_CONFIG)
        .map_err(|e| format!("Не удалось прочитать {SYSTEM_CONFIG}: {e}"))?;

    let (found, server, sig_level) = section_info(&config);

    if found {
        if server.as_deref() == Some(REPO_URL)
            && sig_level.as_deref() == Some("Required TrustedOnly")
        {
            println!("Репозиторий уже настроен правильно.");
            return Ok(());
        }

        return Err(
            "Секция [veyra] уже существует, но её настройки отличаются. \
             Автоматическое изменение отменено."
                .into(),
        );
    }

    run_checked(
        "sudo",
        &["cp", "-n", SYSTEM_CONFIG, "/etc/pacman.conf.veyra.bak"],
    )?;

    let stanza = format!(
        "\n\n# Veyra OS package repository\n\
         [{REPO_NAME}]\n\
         Server = {REPO_URL}\n\
         SigLevel = Required TrustedOnly\n"
    );

    let mut child = Command::new("sudo")
        .args(["tee", "-a", SYSTEM_CONFIG])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("Не удалось запустить sudo tee: {e}"))?;

    if let Some(mut input) = child.stdin.take() {
        input
            .write_all(stanza.as_bytes())
            .map_err(|e| format!("Не удалось передать конфигурацию: {e}"))?;
    }

    let status = child
        .wait()
        .map_err(|e| format!("Не удалось завершить запись конфигурации: {e}"))?;

    if !status.success() {
        return Err(format!("Не удалось обновить {SYSTEM_CONFIG}: {status}"));
    }

    println!("Репозиторий добавлен в {SYSTEM_CONFIG}.");
    println!("Резервная копия: /etc/pacman.conf.veyra.bak");
    Ok(())
}

fn enable_repository() -> Result<(), String> {
    if env::var_os("VEYRA_PACMAN_CONFIG").is_some() {
        return Err(
            "Обнаружен VEYRA_PACMAN_CONFIG. Подключение системного репозитория \
             запрещено в тестовом режиме."
                .into(),
        );
    }

    let config = fs::read_to_string(SYSTEM_CONFIG)
        .map_err(|e| format!("Не удалось прочитать {SYSTEM_CONFIG}: {e}"))?;

    let (found, server, sig_level) = section_info(&config);

    if found
        && server.as_deref() == Some(REPO_URL)
        && sig_level.as_deref() == Some("Required TrustedOnly")
    {
        println!("Veyra Repository уже подключён.");
        return Ok(());
    }

    if found {
        return Err("Секция [veyra] уже существует с другими настройками. \
             Сначала проверь конфигурацию вручную."
            .into());
    }

    println!("Будет изменён системный файл {SYSTEM_CONFIG}.");
    println!("Будет добавлен ключ с отпечатком {FINGERPRINT}.");
    println!(
        "Перед продолжением убедись, что этот отпечаток соответствует официальному ключу Veyra."
    );
    print!("Для подтверждения введи ENABLE VEYRA: ");
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;

    if answer.trim() != "ENABLE VEYRA" {
        println!("Отменено. Изменений не выполнено.");
        return Ok(());
    }

    let key_path = env::temp_dir().join(format!("veyra-public-key-{}.asc", std::process::id()));

    let create_result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path);

    let file = create_result
        .map_err(|e| format!("Не удалось безопасно создать временный файл ключа: {e}"))?;
    drop(file);

    let result = (|| {
        download_and_verify_key(&key_path)?;

        let key_path_string = key_path
            .to_str()
            .ok_or("Некорректный путь к временному файлу ключа")?;

        let add = Command::new("sudo")
            .args(["pacman-key", "--add"])
            .arg(key_path_string)
            .status()
            .map_err(|e| format!("Не удалось выполнить pacman-key --add: {e}"))?;

        if !add.success() {
            return Err("pacman-key не смог импортировать ключ.".into());
        }

        run_checked("sudo", &["pacman-key", "--lsign-key", FINGERPRINT])?;
        append_repository_section()?;

        println!();
        println!("Veyra Repository подключён с обязательной проверкой подписей.");
        println!("Перед поиском и установкой обнови систему через: veyra update");
        Ok(())
    })();

    let _ = fs::remove_file(&key_path);
    result
}

fn show_help() {
    println!("Veyra Repository");
    println!();
    println!("  veyra repo status");
    println!("  veyra repo enable --dry-run");
    println!("  veyra repo enable");
    println!();
    println!("Команда enable без --dry-run запрашивает явное подтверждение.");
}

pub fn run(args: Vec<String>) -> ExitCode {
    let action = args.first().map(String::as_str);

    let result = match action {
        Some("status") if args.len() == 1 => show_status(),
        Some("enable") if args.len() == 2 && args[1] == "--dry-run" => {
            enable_dry_run();
            return ExitCode::SUCCESS;
        }
        Some("enable") if args.len() == 1 => enable_repository(),
        Some("help") | Some("--help") | Some("-h") | None => {
            show_help();
            return ExitCode::SUCCESS;
        }
        _ => {
            show_help();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Veyra Repository: {error}");
            ExitCode::FAILURE
        }
    }
}
