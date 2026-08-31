//! Scalar decoding primitives for the MVP configuration parser.

use edge_domain::{AppError, ErrorCode};

pub(crate) fn parse_string(value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        Ok(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        Err(AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected quoted string: {value}"),
        ))
    }
}

pub(crate) fn parse_string_array(value: &str) -> Result<Vec<String>, AppError> {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected string array: {value}"),
        ));
    }
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|item| parse_string(item.trim()))
        .collect()
}

pub(crate) fn parse_u32(value: &str) -> Result<u32, AppError> {
    value.trim().parse::<u32>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected unsigned integer: {value}"),
        )
    })
}

pub(crate) fn parse_u64(value: &str) -> Result<u64, AppError> {
    value.trim().parse::<u64>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected unsigned integer: {value}"),
        )
    })
}

pub(crate) fn parse_u16(value: &str) -> Result<u16, AppError> {
    value.trim().parse::<u16>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected 16-bit unsigned integer: {value}"),
        )
    })
}

pub(crate) fn parse_u8(value: &str) -> Result<u8, AppError> {
    value.trim().parse::<u8>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected 8-bit unsigned integer: {value}"),
        )
    })
}

pub(crate) fn parse_usize(value: &str) -> Result<usize, AppError> {
    value.trim().parse::<usize>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected unsigned integer: {value}"),
        )
    })
}

pub(crate) fn parse_i32(value: &str) -> Result<i32, AppError> {
    value.trim().parse::<i32>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected signed integer: {value}"),
        )
    })
}

pub(crate) fn parse_bool(value: &str) -> Result<bool, AppError> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected boolean: {value}"),
        )),
    }
}
