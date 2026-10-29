use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureTableStatus {
    Absent,
    Present { size_bytes: u64, entries: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub struct IntegrityReport {
    pub sha256: String,
    pub signature_table: Result<SignatureTableStatus, String>,
}

fn sha256_reader<R: Read>(reader: &mut R) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("Ошибка чтения при SHA-256: {error}"))?;

        if count == 0 {
            break;
        }

        hasher.update(&buffer[..count]);
    }

    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);

    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }

    Ok(output)
}

fn read_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buffer: &mut [u8],
    file_size: u64,
) -> Result<(), String> {
    let length = buffer.len() as u64;

    let end = offset
        .checked_add(length)
        .ok_or("Переполнение смещения файла.".to_string())?;

    if end > file_size {
        return Err("Чтение выходит за границы файла.".into());
    }

    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| format!("Ошибка перехода по файлу: {error}"))?;

    reader
        .read_exact(buffer)
        .map_err(|error| format!("Ошибка чтения файла: {error}"))
}

fn read_u16<R: Read + Seek>(reader: &mut R, offset: u64, file_size: u64) -> Result<u16, String> {
    let mut bytes = [0u8; 2];
    read_at(reader, offset, &mut bytes, file_size)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32<R: Read + Seek>(reader: &mut R, offset: u64, file_size: u64) -> Result<u32, String> {
    let mut bytes = [0u8; 4];
    read_at(reader, offset, &mut bytes, file_size)?;
    Ok(u32::from_le_bytes(bytes))
}

fn inspect_security_table<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
) -> Result<SignatureTableStatus, String> {
    if file_size < 64 {
        return Err("Файл слишком мал для заголовка PE.".into());
    }

    let mut dos = [0u8; 64];
    read_at(reader, 0, &mut dos, file_size)?;

    if &dos[..2] != b"MZ" {
        return Err("Нет сигнатуры MZ.".into());
    }

    let pe_offset = u32::from_le_bytes(
        dos[0x3c..0x40]
            .try_into()
            .map_err(|_| "Некорректный DOS-заголовок.".to_string())?,
    ) as u64;

    if pe_offset < 64 {
        return Err("Некорректное смещение заголовка PE.".into());
    }

    let mut coff = [0u8; 24];
    read_at(reader, pe_offset, &mut coff, file_size)?;

    if &coff[..4] != b"PE\0\0" {
        return Err("Сигнатура PE не найдена.".into());
    }

    let section_count = u16::from_le_bytes([coff[6], coff[7]]) as u64;
    let optional_size = u16::from_le_bytes([coff[20], coff[21]]) as u64;

    if section_count == 0 || section_count > 4096 {
        return Err("Недопустимое количество секций PE.".into());
    }

    let optional_start = pe_offset
        .checked_add(24)
        .ok_or("Переполнение смещения Optional Header.".to_string())?;

    let magic = read_u16(reader, optional_start, file_size)?;

    let (number_of_directories_offset, directories_offset) = match magic {
        0x10b => (92u64, 96u64),
        0x20b => (108u64, 112u64),
        _ => return Err("Неизвестный формат Optional Header.".into()),
    };

    if optional_size < number_of_directories_offset + 4 {
        return Err("Optional Header слишком короткий.".into());
    }

    let directory_count = read_u32(
        reader,
        optional_start + number_of_directories_offset,
        file_size,
    )? as u64;

    // Индекс 4 — Security Directory.
    if directory_count <= 4 {
        return Ok(SignatureTableStatus::Absent);
    }

    let needed_size = directories_offset + 5 * 8;

    if optional_size < needed_size {
        return Err("В Optional Header отсутствует полный Security Directory.".into());
    }

    let certificate_entry = optional_start + directories_offset + 4 * 8;
    let certificate_offset = read_u32(reader, certificate_entry, file_size)? as u64;
    let certificate_size = read_u32(reader, certificate_entry + 4, file_size)? as u64;

    if certificate_offset == 0 && certificate_size == 0 {
        return Ok(SignatureTableStatus::Absent);
    }

    if certificate_offset == 0 || certificate_size == 0 {
        return Err("Неполная запись Security Directory.".into());
    }

    // Исправление Clippy: проверяем выравнивание напрямую.
    if !certificate_offset.is_multiple_of(8) || !certificate_size.is_multiple_of(8) {
        return Err("Таблица сертификатов не выровнена по 8 байтам.".into());
    }

    let optional_end = optional_start
        .checked_add(optional_size)
        .ok_or("Переполнение границ Optional Header.".to_string())?;

    if certificate_offset < optional_end {
        return Err("Таблица сертификатов пересекается с заголовками PE.".into());
    }

    let certificate_end = certificate_offset
        .checked_add(certificate_size)
        .ok_or("Переполнение границ таблицы сертификатов.".to_string())?;

    if certificate_end > file_size {
        return Err("Таблица сертификатов выходит за границы файла.".into());
    }

    let section_table = optional_end;

    let section_table_size = section_count
        .checked_mul(40)
        .ok_or("Переполнение размера таблицы секций.".to_string())?;

    let section_table_end = section_table
        .checked_add(section_table_size)
        .ok_or("Переполнение конца таблицы секций.".to_string())?;

    if section_table_end > file_size {
        return Err("Таблица секций выходит за границы файла.".into());
    }

    for index in 0..section_count {
        let header_offset = section_table
            .checked_add(
                index
                    .checked_mul(40)
                    .ok_or("Переполнение смещения секции.".to_string())?,
            )
            .ok_or("Переполнение смещения секции.".to_string())?;

        let mut header = [0u8; 40];
        read_at(reader, header_offset, &mut header, file_size)?;

        let raw_size = u32::from_le_bytes(
            header[16..20]
                .try_into()
                .map_err(|_| "Некорректный размер секции.".to_string())?,
        ) as u64;

        let raw_offset = u32::from_le_bytes(
            header[20..24]
                .try_into()
                .map_err(|_| "Некорректное смещение секции.".to_string())?,
        ) as u64;

        if raw_size == 0 {
            continue;
        }

        let raw_end = raw_offset
            .checked_add(raw_size)
            .ok_or("Переполнение границ данных секции.".to_string())?;

        if raw_offset < section_table_end || raw_end > file_size {
            return Err("Данные секции PE выходят за допустимые границы.".into());
        }

        if raw_offset < certificate_end && certificate_offset < raw_end {
            return Err("Таблица сертификатов перекрывает данные секции.".into());
        }
    }

    let mut cursor = certificate_offset;
    let mut entries = 0usize;

    while cursor < certificate_end {
        if certificate_end - cursor < 8 {
            return Err("Неполный заголовок WIN_CERTIFICATE.".into());
        }

        let length = read_u32(reader, cursor, file_size)? as u64;

        if length < 8 {
            return Err("Некорректная длина WIN_CERTIFICATE.".into());
        }

        let record_end = cursor
            .checked_add(length)
            .ok_or("Переполнение длины WIN_CERTIFICATE.".to_string())?;

        if record_end > certificate_end {
            return Err("WIN_CERTIFICATE выходит за границы таблицы.".into());
        }

        let aligned_length = length
            .checked_add(7)
            .ok_or("Переполнение выравнивания сертификата.".to_string())?
            & !7;

        cursor = cursor
            .checked_add(aligned_length)
            .ok_or("Переполнение позиции сертификата.".to_string())?;

        if cursor > certificate_end {
            return Err("Запись сертификата нарушает границы выравнивания.".into());
        }

        entries += 1;
    }

    if entries == 0 {
        return Err("Таблица сертификатов не содержит записей.".into());
    }

    Ok(SignatureTableStatus::Present {
        size_bytes: certificate_size,
        entries,
    })
}

pub fn inspect(path: &Path) -> Result<IntegrityReport, String> {
    let mut file =
        File::open(path).map_err(|error| format!("Не удалось открыть файл для чтения: {error}"))?;

    let file_size = file
        .metadata()
        .map_err(|error| format!("Не удалось получить размер файла: {error}"))?
        .len();

    let sha256 = sha256_reader(&mut file)?;
    let signature_table = inspect_security_table(&mut file, file_size);

    Ok(IntegrityReport {
        sha256,
        signature_table,
    })
}

#[cfg(test)]
mod tests {
    use super::{SignatureTableStatus, inspect_security_table, sha256_reader};
    use std::io::Cursor;

    fn make_test_pe(with_certificate: bool) -> Vec<u8> {
        const PE_OFFSET: usize = 0x80;
        const OPTIONAL_SIZE: usize = 0xF0;

        let optional_start = PE_OFFSET + 24;
        let section_table = optional_start + OPTIONAL_SIZE;
        let section_data_offset = 0x200;
        let certificate_offset = 0x218;

        let file_size = if with_certificate {
            certificate_offset + 8
        } else {
            section_data_offset + 16
        };

        let mut bytes = vec![0u8; file_size];

        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        bytes[PE_OFFSET + 4..PE_OFFSET + 6].copy_from_slice(&0x8664u16.to_le_bytes());

        bytes[PE_OFFSET + 6..PE_OFFSET + 8].copy_from_slice(&1u16.to_le_bytes());

        bytes[PE_OFFSET + 20..PE_OFFSET + 22]
            .copy_from_slice(&(OPTIONAL_SIZE as u16).to_le_bytes());

        bytes[optional_start..optional_start + 2].copy_from_slice(&0x20bu16.to_le_bytes());

        bytes[optional_start + 108..optional_start + 112].copy_from_slice(&16u32.to_le_bytes());

        let security_entry = optional_start + 112 + 4 * 8;

        if with_certificate {
            bytes[security_entry..security_entry + 4]
                .copy_from_slice(&(certificate_offset as u32).to_le_bytes());

            bytes[security_entry + 4..security_entry + 8].copy_from_slice(&8u32.to_le_bytes());
        }

        bytes[section_table..section_table + 6].copy_from_slice(b".linux");

        bytes[section_table + 16..section_table + 20].copy_from_slice(&16u32.to_le_bytes());

        bytes[section_table + 20..section_table + 24]
            .copy_from_slice(&(section_data_offset as u32).to_le_bytes());

        if with_certificate {
            bytes[certificate_offset..certificate_offset + 4].copy_from_slice(&8u32.to_le_bytes());

            bytes[certificate_offset + 4..certificate_offset + 6]
                .copy_from_slice(&0x0200u16.to_le_bytes());

            bytes[certificate_offset + 6..certificate_offset + 8]
                .copy_from_slice(&0x0002u16.to_le_bytes());
        }

        bytes
    }

    #[test]
    fn sha256_matches_known_vector() {
        let mut data = Cursor::new(b"abc");
        let hash = sha256_reader(&mut data).unwrap();

        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223\
             b00361a396177a9cb410ff61f20015ad"
                .replace(' ', "")
        );
    }

    #[test]
    fn detects_absent_certificate_table() {
        let bytes = make_test_pe(false);
        let size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            inspect_security_table(&mut cursor, size).unwrap(),
            SignatureTableStatus::Absent
        );
    }

    #[test]
    fn detects_structural_certificate_table() {
        let bytes = make_test_pe(true);
        let size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            inspect_security_table(&mut cursor, size).unwrap(),
            SignatureTableStatus::Present {
                size_bytes: 8,
                entries: 1
            }
        );
    }

    #[test]
    fn rejects_certificate_table_outside_file() {
        let mut bytes = make_test_pe(true);
        let optional_start = 0x80 + 24;
        let security_entry = optional_start + 112 + 4 * 8;

        bytes[security_entry..security_entry + 4].copy_from_slice(&0x1000u32.to_le_bytes());

        let size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);

        assert!(inspect_security_table(&mut cursor, size).is_err());
    }
}
