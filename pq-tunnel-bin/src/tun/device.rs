//! Portable TUN device abstraction (D33 §2.2).
//!
//! Wraps the `tun` crate's synchronous device. Async I/O is handled by the
//! drivers via `tokio::task::spawn_blocking` so the workspace stays on the
//! pinned Tokio 1.52 (avoiding a lockfile drift with the fuzz workspace).

use std::io::{Read, Write};
use std::net::IpAddr;
use tun::AbstractDevice;

pub fn create_device(name: &str) -> std::io::Result<tun::Device> {
    let mut config = tun::Configuration::default();
    config.tun_name(name).mtu(crate::tun::INNER_MTU).up();
    config.layer(tun::Layer::L3);
    tun::create(&config).map_err(std::io::Error::other)
}

pub fn set_v4_address(dev: &mut tun::Device, ip: IpAddr) -> std::io::Result<()> {
    dev.set_address(ip).map_err(std::io::Error::other)
}

pub struct TunDeviceImpl {
    dev: tun::Device,
}

impl TunDeviceImpl {
    pub fn new(dev: tun::Device) -> Self {
        Self { dev }
    }
    pub fn inner_mut(&mut self) -> &mut tun::Device {
        &mut self.dev
    }
}

impl crate::tun::TunDevice for TunDeviceImpl {
    fn read_packet(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let n = self.dev.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
    fn write_packet(&mut self, pkt: &[u8]) -> std::io::Result<usize> {
        self.dev.write(pkt)
    }
    fn mtu(&self) -> u16 {
        self.dev.mtu().unwrap_or(crate::tun::INNER_MTU)
    }
    fn close(&mut self) {}
}

pub async fn open_tun(name: &str) -> std::io::Result<tun::Device> {
    let name = name.to_string();
    tokio::task::spawn_blocking(move || create_device(&name))
        .await
        .map_err(std::io::Error::other)?
}
