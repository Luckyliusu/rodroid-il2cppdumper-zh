#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("无效的元数据文件: {0}")]
    InvalidMetadata(String),

    #[error("不支持的元数据版本: {0}")]
    UnsupportedVersion(i32),

    #[error("地址 0x{0:x} 不在任何段内")]
    AddressNotMapped(u64),

    #[error("无效的二进制格式: {0}")]
    InvalidFormat(String),

    #[error(
        "读取越界: 偏移 0x{offset:x}，大小 {size} \
         （文件被截断、偏移错误，或数据已加密/损坏）"
    )]
    OutOfBounds { offset: u64, size: usize },

    #[error("无效的数组大小: count={count}, element_size={elem_size} ({context})")]
    InvalidArraySize {
        count: u64,
        elem_size: usize,
        context: String,
    },

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("循环的值类型依赖: {0}")]
    CyclicDependency(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Enrich low-level read failures with actionable metadata-protection hints.
    pub fn with_metadata_context(self, file_len: u64) -> Self {
        const HINT: &str = "\
常见原因: global-metadata.dat 已加密/混淆、提取不完整，或 Unity 布局不匹配。 \
有效文件以 magic AF 1B B1 FA 开头。受保护的游戏通常需要先获取运行时内存转储， \
在转储前得到已解密的元数据。";

        match self {
            Error::OutOfBounds { offset, size } => Error::InvalidMetadata(format!(
                "解析表时读取超出元数据末尾 \
                 （偏移 0x{offset:X}，需要 {size} 字节，文件大小 {file_len}）。{HINT}"
            )),
            Error::Io(ref e)
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.to_string().contains("fill whole buffer") =>
            {
                Error::InvalidMetadata(format!(
                    "解析表时元数据文件意外结束（文件大小 {file_len}）。{HINT}"
                ))
            }
            Error::InvalidArraySize {
                count,
                elem_size,
                context,
            } => Error::InvalidMetadata(format!(
                "'{context}' 中元数据表大小异常 \
                 （count={count}, element_size={elem_size}, 文件大小 {file_len}）。 \
                 头部字段疑似损坏 — 通常是加密或文件被截断所致。{HINT}"
            )),
            other => other,
        }
    }

    /// Short UI-facing string (Android / Tauri toast).
    pub fn user_message(&self) -> String {
        match self {
            Error::InvalidMetadata(msg) => format!("元数据错误: {msg}"),
            Error::UnsupportedVersion(v) => format!(
                "元数据错误: 不支持的元数据版本 {v}。 \
                 请更新转储器，或检查文件是否已损坏/加密。"
            ),
            Error::OutOfBounds { offset, size } => format!(
                "元数据错误: 读取超出文件末尾（偏移 0x{offset:X}，大小 {size}）。 \
                 文件可能已被截断或加密。"
            ),
            Error::InvalidArraySize { context, .. } => format!(
                "元数据错误: 表大小无效 ({context})。 \
                 文件可能已加密或损坏。"
            ),
            Error::Io(e)
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.to_string().contains("fill whole buffer") =>
            {
                "元数据错误: 读取元数据时文件意外结束 \
                 （通常是已加密、被截断，或文件不对）。"
                    .into()
            }
            other => other.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
