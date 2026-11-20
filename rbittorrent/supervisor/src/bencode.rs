//! Minimal, bounded bencode reader (BEP 3) for qBittorrent's `.fastresume`
//! files. Read-only, zero-copy, no recursion deeper than [`MAX_DEPTH`].

use anyhow::{Result, bail};

const MAX_DEPTH: usize = 64;
/// Values in one document. Each costs ~40 bytes, so a crafted 32 MiB file of
/// empty lists cannot turn into gigabytes; real `.fastresume` files hold a
/// few thousand.
pub const MAX_VALUES: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    List(Vec<Value<'a>>),
    /// Keys in file order (bencode requires them sorted; not enforced).
    Dict(Vec<(&'a [u8], Value<'a>)>),
}

impl<'a> Value<'a> {
    /// Dictionary lookup.
    pub fn get(&self, key: &str) -> Option<&Value<'a>> {
        match self {
            Value::Dict(items) => items
                .iter()
                .find(|(k, _)| *k == key.as_bytes())
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// A UTF-8 byte string.
    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            Value::Bytes(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }
}

/// Decodes one complete bencoded value; trailing bytes are an error.
pub fn decode(input: &[u8]) -> Result<Value<'_>> {
    let mut pos = 0;
    let mut budget = MAX_VALUES;
    let v = value(input, &mut pos, 0, &mut budget)?;
    if pos != input.len() {
        bail!("bencode: {} trailing bytes", input.len() - pos);
    }
    Ok(v)
}

fn value<'a>(
    input: &'a [u8],
    pos: &mut usize,
    depth: usize,
    budget: &mut usize,
) -> Result<Value<'a>> {
    if depth > MAX_DEPTH {
        bail!("bencode: nested too deeply");
    }
    *budget = budget
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("bencode: more than {MAX_VALUES} values"))?;
    match input.get(*pos) {
        Some(b'i') => {
            *pos += 1;
            let end = find(input, *pos, b'e')?;
            let text = std::str::from_utf8(slice(input, *pos, end)?)?;
            if !canonical_int(text) {
                bail!("bencode: malformed integer {text:?}");
            }
            *pos = end + 1;
            Ok(Value::Int(text.parse()?))
        }
        Some(b'l') => {
            *pos += 1;
            let mut items = Vec::new();
            while input.get(*pos) != Some(&b'e') {
                items.push(value(input, pos, depth + 1, budget)?);
            }
            *pos += 1;
            Ok(Value::List(items))
        }
        Some(b'd') => {
            *pos += 1;
            let mut items = Vec::new();
            while input.get(*pos) != Some(&b'e') {
                let Value::Bytes(key) = bytes(input, pos)? else {
                    unreachable!("bytes() only returns Value::Bytes")
                };
                items.push((key, value(input, pos, depth + 1, budget)?));
            }
            *pos += 1;
            Ok(Value::Dict(items))
        }
        Some(b'0'..=b'9') => bytes(input, pos),
        Some(b) => bail!("bencode: unexpected byte {b:#04x} at {pos}"),
        None => bail!("bencode: unexpected end of input"),
    }
}

/// `0`, or digits without a leading zero, optionally negative (not `-0`).
/// Rust's parser alone would also take `+5` and `007`.
fn canonical_int(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let all_digits = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    all_digits && (digits == "0" && !text.starts_with('-') || !digits.starts_with('0'))
}

fn bytes<'a>(input: &'a [u8], pos: &mut usize) -> Result<Value<'a>> {
    let colon = find(input, *pos, b':')?;
    let digits = std::str::from_utf8(slice(input, *pos, colon)?)?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        bail!("bencode: malformed string length {digits:?}");
    }
    let len: usize = digits.parse()?;
    let start = colon + 1;
    let end = start
        .checked_add(len)
        .filter(|e| *e <= input.len())
        .ok_or_else(|| anyhow::anyhow!("bencode: string runs past the end"))?;
    *pos = end;
    Ok(Value::Bytes(slice(input, start, end)?))
}

fn slice(input: &[u8], from: usize, to: usize) -> Result<&[u8]> {
    input
        .get(from..to)
        .ok_or_else(|| anyhow::anyhow!("bencode: unexpected end of input"))
}

fn find(input: &[u8], from: usize, byte: u8) -> Result<usize> {
    input
        .get(from..)
        .and_then(|rest| rest.iter().position(|b| *b == byte))
        .map(|i| from + i)
        .ok_or_else(|| anyhow::anyhow!("bencode: unexpected end of input"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_nested_values() {
        let v = decode(b"d4:infod4:name3:abce4:listli1ei-2ee9:save_path6:/share3:numi0ee").unwrap();
        assert_eq!(v.get("save_path").and_then(Value::as_str), Some("/share"));
        assert_eq!(v.get("num").and_then(Value::as_int), Some(0));
        assert_eq!(
            v.get("info")
                .and_then(|i| i.get("name"))
                .and_then(Value::as_str),
            Some("abc")
        );
        assert_eq!(
            v.get("list"),
            Some(&Value::List(vec![Value::Int(1), Value::Int(-2)]))
        );
        assert!(v.get("missing").is_none());
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            &b"i01e"[..],
            b"i-0e",
            b"ie",
            b"5:abc",
            b"d3:keye",
            b"li1e",
            b"x",
            b"",
            b"i1ei2e",
            b"99999999999999999999999:a",
            b"i+5e",
            b"i-e",
            b"i1.5e",
            b"+1:a",
            b"01:a",
        ] {
            assert!(decode(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let deep = "l".repeat(100) + &"e".repeat(100);
        assert!(decode(deep.as_bytes()).is_err());
        assert_eq!(decode(b"i0e").unwrap(), Value::Int(0));
        assert_eq!(decode(b"i-12e").unwrap(), Value::Int(-12));
        assert_eq!(decode(b"0:").unwrap(), Value::Bytes(b""));
    }

    #[test]
    fn the_number_of_values_is_capped() {
        let many = |n: usize| format!("l{}e", "le".repeat(n));
        assert!(decode(many(MAX_VALUES - 1).as_bytes()).is_ok());
        let err = decode(many(MAX_VALUES).as_bytes()).unwrap_err();
        assert!(err.to_string().contains("more than"), "{err}");
    }
}
