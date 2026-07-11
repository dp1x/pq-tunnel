use std::io;
use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN device error: {0}")]
    Device(String),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("TUN device not configured")]
    NotConfigured,
}

impl From<TunError> for io::Error {
    fn from(e: TunError) -> Self {
        match e {
            TunError::Io(io) => io,
            other => io::Error::other(other),
        }
    }
}

pub struct TunDevice {
    device: tun::AsyncDevice,
}

impl TunDevice {
    pub fn create(name: &str, addr: IpAddr, netmask: IpAddr, mtu: u16) -> Result<Self, TunError> {
        let mut config = tun::Configuration::default();
        config
            .tun_name(name)
            .address(addr)
            .netmask(netmask)
            .mtu(mtu)
            .up();

        #[cfg(target_os = "linux")]
        config.platform_config(|pc| {
            pc.ensure_root_privileges(true);
        });

        let dev = tun::create_as_async(&config)
            .map_err(|e| TunError::Device(format!("create failed: {}", e)))?;

        Ok(TunDevice { device: dev })
    }

    pub fn split(self) -> (TunReader, TunWriter) {
        match self.device.split() {
            Ok((writer, reader)) => (TunReader { reader }, TunWriter { writer }),
            Err(e) => panic!("split must succeed: {}", e),
        }
    }
}

pub struct TunReader {
    reader: tun::DeviceReader,
}

impl TunReader {
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        use tokio::io::AsyncReadExt;
        self.reader
            .read(buf)
            .await
            .map_err(|e| TunError::Device(format!("recv: {}", e)))
    }
}

pub struct TunWriter {
    writer: tun::DeviceWriter,
}

impl TunWriter {
    pub async fn write_packet(&mut self, buf: &[u8]) -> Result<(), TunError> {
        use tokio::io::AsyncWriteExt;
        self.writer
            .write_all(buf)
            .await
            .map_err(|e| TunError::Device(format!("send: {}", e)))?;
        Ok(())
    }
}
