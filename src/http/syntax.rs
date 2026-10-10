pub(crate) fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

pub(crate) fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().copied().all(is_token_byte)
}

pub(crate) fn is_field_value(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&byte| (byte >= 0x20 || byte == b'\t') && byte != 0x7f)
}

pub(super) fn parse_field(line: &str) -> std::io::Result<(&str, &str)> {
    let (name, value) = line.split_once(':').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP field is missing a colon",
        )
    })?;
    if !is_token(name.as_bytes()) || !is_field_value(value.as_bytes()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid HTTP field syntax",
        ));
    }
    Ok((name, value.trim_matches([' ', '\t'])))
}
