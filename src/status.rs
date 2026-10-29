use std::fs;
use std::process::{Command, ExitCode};

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let result = Command::new(program).args(args).output().ok()?;
    if !result.status.success() {
        return None;
    }

    let value = String::from_utf8_lossy(&result.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn parse_os_name(contents: &str) -> Option<String> {
    let raw = contents.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key == "PRETTY_NAME").then_some(value.trim())
    })?;

    let value = if let Some(value) = raw.strip_prefix('"') {
        value.strip_suffix('"')?
    } else {
        if raw.ends_with('"') {
            return None;
        }
        raw
    };

    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn uptime_seconds(contents: &str) -> Option<u64> {
    let seconds = contents.split_whitespace().next()?.parse::<f64>().ok()?;

    if !seconds.is_finite() || seconds < 0.0 || seconds >= u64::MAX as f64 {
        return None;
    }

    Some(seconds as u64)
}

fn format_uptime(seconds: u64) -> String {
    format!(
        "{} д. {} ч. {} мин.",
        seconds / 86_400,
        (seconds % 86_400) / 3_600,
        (seconds % 3_600) / 60
    )
}

fn memory_kib(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name != key {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

pub fn run() -> ExitCode {
    println!();
    println!("==================================");
    println!("       VEYRA SYSTEM STATUS");
    println!("==================================");

    let os = fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| parse_os_name(&text))
        .unwrap_or_else(|| "Неизвестная Linux-система".into());
    println!("Операционная система: {os}");

    let hostname = fs::read_to_string("/etc/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "неизвестно".into());
    println!("Имя компьютера:      {hostname}");

    println!(
        "Версия ядра:         {}",
        command_output("uname", &["-r"]).unwrap_or_else(|| "недоступна".into())
    );

    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|contents| uptime_seconds(&contents))
        .map(format_uptime)
        .unwrap_or_else(|| "недоступно".into());
    println!("Время работы:        {uptime}");

    let memory = fs::read_to_string("/proc/meminfo").ok();
    let memory_display = memory
        .as_deref()
        .and_then(|text| {
            let total = memory_kib(text, "MemTotal")?;
            let available = memory_kib(text, "MemAvailable")?;
            (total > 0 && available <= total).then_some((total, available))
        })
        .map(|(total, available)| {
            let gib = 1024.0 * 1024.0;
            format!(
                "{:.2} / {:.2} GiB",
                (total - available) as f64 / gib,
                total as f64 / gib
            )
        })
        .unwrap_or_else(|| "недоступно".into());
    println!("Оперативная память: {memory_display}");

    let load = fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|contents| {
            let values: Vec<_> = contents.split_whitespace().take(3).collect();
            (values.len() == 3).then(|| values.join(" "))
        })
        .unwrap_or_else(|| "недоступна".into());
    println!("Средняя нагрузка:   {load}");

    println!("\nКорневой раздел:");
    match command_output("df", &["-h", "/"]) {
        Some(disk) => println!("{disk}"),
        None => println!("Не удалось получить информацию о диске."),
    }

    println!("==================================");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{format_uptime, memory_kib, parse_os_name, uptime_seconds};

    #[test]
    fn parses_veyra_os_name() {
        assert_eq!(
            parse_os_name("NAME=Veyra\nPRETTY_NAME=\"Veyra OS Alpha\"\n"),
            Some("Veyra OS Alpha".into())
        );
    }

    #[test]
    fn rejects_missing_or_empty_os_name() {
        assert_eq!(parse_os_name("NAME=Veyra\n"), None);
        assert_eq!(parse_os_name("PRETTY_NAME=\"\"\n"), None);
        assert_eq!(parse_os_name("PRETTY_NAME=\"broken\n"), None);
    }

    #[test]
    fn parses_uptime_seconds() {
        assert_eq!(uptime_seconds("90061.8 1234.5"), Some(90_061));
        assert_eq!(uptime_seconds("invalid"), None);
        assert_eq!(uptime_seconds("-1.0"), None);
        assert_eq!(uptime_seconds("NaN"), None);
    }

    #[test]
    fn formats_uptime() {
        assert_eq!(format_uptime(90_061), "1 д. 1 ч. 1 мин.");
    }

    #[test]
    fn parses_memory_values() {
        let text = "MemTotal: 16000000 kB\nMemAvailable: 6000000 kB\n";
        assert_eq!(memory_kib(text, "MemTotal"), Some(16_000_000));
        assert_eq!(memory_kib(text, "MemAvailable"), Some(6_000_000));
        assert_eq!(memory_kib(text, "Missing"), None);
    }
}
