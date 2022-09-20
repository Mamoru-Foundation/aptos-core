#[derive(thiserror::Error, Debug)]
pub enum AptosSnifferError {
    #[error(transparent)]
    SnifferError(#[from] mamoru_sniffer::SnifferError),

    #[error(transparent)]
    DataError(#[from] mamoru_sniffer::core::DataError),
}
