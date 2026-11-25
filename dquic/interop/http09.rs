use std::{
    io,
    path::{Component, Path, PathBuf},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const ALPN: &[u8] = b"hq-interop";

pub(crate) struct Request {
    pub authority: String,
    pub path: String,
    pub filename: String,
}

impl Request {
    pub fn parse(url: &str) -> io::Result<Self> {
        let (authority, path) = url
            .strip_prefix("https://")
            .and_then(|url| url.split_once('/'))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected https://host/path"))?;
        if authority.is_empty()
            || authority.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || b"@?#\\".contains(&byte))
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid URL authority"));
        }
        let path = format!("/{path}");
        let relative = relative_path(&path)?;
        let filename = relative.file_name().unwrap().to_string_lossy().into_owned();
        Ok(Self { authority: authority.to_owned(), path, filename })
    }
}

pub(crate) async fn serve(reader: impl AsyncRead + Unpin, mut writer: impl AsyncWrite + Unpin, root: &Path) -> io::Result<u64> {
    let mut request = Vec::new();
    reader.take(8193).read_to_end(&mut request).await?;
    if request.len() > 8192 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/0.9 request is too long"));
    }
    let path = std::str::from_utf8(&request)
        .ok()
        .and_then(|request| request.strip_prefix("GET "))
        .and_then(|path| path.strip_suffix("\r\n"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected GET /path followed by CRLF and FIN"))?;
    let relative = relative_path(path)?;
    let root = tokio::fs::canonicalize(root).await?;
    let file = tokio::fs::canonicalize(root.join(relative)).await?;
    if !file.starts_with(&root) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "request escapes the file root"));
    }
    let mut file = tokio::fs::File::open(file).await?;
    let bytes = tokio::io::copy(&mut file, &mut writer).await?;
    writer.shutdown().await?;
    Ok(bytes)
}

pub(crate) async fn download(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    path: &str,
    mut output: impl AsyncWrite + Unpin,
) -> io::Result<u64> {
    writer.write_all(format!("GET {path}\r\n").as_bytes()).await?;
    writer.shutdown().await?;
    let bytes = tokio::io::copy(&mut reader, &mut output).await?;
    output.flush().await?;
    Ok(bytes)
}

fn relative_path(path: &str) -> io::Result<PathBuf> {
    let relative = path.strip_prefix('/').map(Path::new);
    match relative {
        Some(relative)
            if !relative.as_os_str().is_empty()
                && relative.components().all(|component| matches!(component, Component::Normal(_)))
                && !path.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || b"\\?#".contains(&byte)) =>
        {
            Ok(relative.to_owned())
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid HTTP/0.9 file path")),
    }
}
