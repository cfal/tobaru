use tokio::io::AsyncWriteExt;

#[inline]
pub fn allocate_vec(len: usize) -> Vec<u8> {
    vec![0; len]
}

// a cancellable alternative to AsyncWriteExt::write_all
pub async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut i = 0;
    let n = buf.len();
    while i < n {
        let n = stream.write(&buf[i..]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "Failed to write buffer",
            ));
        }
        i += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_all_rejects_zero_progress_and_accepts_empty_input() {
        let mut bytes = [0u8; 2];
        let mut output = std::io::Cursor::new(bytes.as_mut_slice());
        let error = write_all(&mut output, b"abc").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
        write_all(&mut output, b"").await.unwrap();
    }

    #[test]
    fn read_buffers_are_initialized() {
        assert_eq!(allocate_vec(4), [0; 4]);
        assert!(allocate_vec(0).is_empty());
    }
}
