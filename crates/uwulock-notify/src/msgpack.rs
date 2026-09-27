//! Just enough MessagePack for SignalR's messages: nil, booleans, integers, strings, arrays, maps
//! and the timestamp extension. SignalR frames each message with its length in front, seven bits
//! a byte.

/// A value to encode.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Value>),
    /// Keys and values, in order.
    Map(Vec<(Value, Value)>),
    /// Seconds and nanoseconds since 1970.
    Timestamp(i64, u32),
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Value::Str(text.to_string())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Value::Str(text)
    }
}

impl From<i64> for Value {
    fn from(number: i64) -> Self {
        Value::Int(number)
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        value.map_or(Value::Nil, Into::into)
    }
}

fn length(out: &mut Vec<u8>, len: usize, fix: u8, fix_max: usize, tag16: u8, tag32: u8) {
    if len <= fix_max {
        out.push(fix | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(tag16);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(tag32);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

pub fn encode(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Nil => out.push(0xc0),
        Value::Bool(false) => out.push(0xc2),
        Value::Bool(true) => out.push(0xc3),
        Value::Int(number) => match *number {
            0..=0x7f => out.push(*number as u8),
            -32..=-1 => out.push(*number as i8 as u8),
            n if n >= 0 && n <= u32::MAX as i64 => {
                out.push(0xce);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            n => {
                out.push(0xd3);
                out.extend_from_slice(&n.to_be_bytes());
            }
        },
        Value::Str(text) => {
            if text.len() < 32 {
                out.push(0xa0 | text.len() as u8);
            } else if text.len() <= u8::MAX as usize {
                out.push(0xd9);
                out.push(text.len() as u8);
            } else {
                length(out, text.len(), 0xa0, 0, 0xda, 0xdb);
            }
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            length(out, items.len(), 0x90, 15, 0xdc, 0xdd);
            for item in items {
                encode(item, out);
            }
        }
        Value::Map(entries) => {
            length(out, entries.len(), 0x80, 15, 0xde, 0xdf);
            for (key, value) in entries {
                encode(key, out);
                encode(value, out);
            }
        }
        Value::Timestamp(seconds, nanos) => {
            // timestamp 64: 30 bits of nanoseconds, 34 of seconds.
            out.extend_from_slice(&[0xd7, 0xff]);
            let packed = (u64::from(*nanos) << 34) | (*seconds as u64 & 0x3_ffff_ffff);
            out.extend_from_slice(&packed.to_be_bytes());
        }
    }
}

/// A message as SignalR sends it over the wire: its length, then the message.
pub fn frame(value: &Value) -> Vec<u8> {
    let mut body = Vec::new();
    encode(value, &mut body);
    let mut out = Vec::with_capacity(body.len() + 5);
    let mut size = body.len();
    loop {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if size == 0 {
            break;
        }
    }
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(value: Value) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&value, &mut out);
        out
    }

    #[test]
    fn values_encode_as_messagepack_does() {
        assert_eq!(bytes(Value::Nil), [0xc0]);
        assert_eq!(bytes(Value::Int(1)), [0x01]);
        assert_eq!(bytes(Value::Int(-1)), [0xff]);
        assert_eq!(bytes(Value::Int(300)), [0xce, 0, 0, 1, 0x2c]);
        assert_eq!(bytes("Id".into()), [0xa2, b'I', b'd']);
        let long = "x".repeat(40);
        assert_eq!(bytes(long.clone().into())[..2], [0xd9, 40]);
        assert_eq!(bytes(Value::Array(vec![Value::Nil; 2])), [0x92, 0xc0, 0xc0]);
        assert_eq!(bytes(Value::Map(vec![("a".into(), Value::Bool(true))])), [0x81, 0xa1, b'a', 0xc3]);
        assert_eq!(bytes(Value::Timestamp(1, 0)), [0xd7, 0xff, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn a_frame_carries_its_length() {
        let framed = frame(&Value::Array(vec![Value::Int(6)]));
        assert_eq!(framed, [2, 0x91, 0x06], "a ping");
        let big = frame(&Value::Str("y".repeat(200)));
        assert_eq!(&big[..2], &[0xca, 0x01], "202 bytes: two length bytes");
    }
}
