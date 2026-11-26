use std::io;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Initialize only the facilities needed by the loopback validation firmware.
/// The build timestamp is a test clock, not a substitute for production SNTP.
pub fn initialize() -> Result<(), Error> {
    esp_idf_sys::link_patches();
    let eventfd = esp_idf_sys::esp_vfs_eventfd_config_t { max_fds: 4 };
    let clock = esp_idf_sys::timeval { tv_sec: env!("DQUIC_TEST_UNIX_TIME").parse()?, tv_usec: 0 };
    // These process-wide facilities are initialized once before Tokio or TLS.
    unsafe {
        esp_idf_sys::esp!(esp_idf_sys::esp_netif_init())?;
        esp_idf_sys::esp!(esp_idf_sys::esp_vfs_eventfd_register(&eventfd))?;
        if esp_idf_sys::settimeofday(&clock, std::ptr::null()) != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // Loopback has no Wi-Fi/BT entropy source. Keep SAR entropy enabled.
        esp_idf_sys::bootloader_random_enable();
    }
    report_heap("initialized");
    Ok(())
}

pub fn report_heap(stage: &str) {
    // ESP-IDF's heap statistics are valid after startup, including in QEMU.
    unsafe {
        println!("heap {stage}: free={} minimum={}", esp_idf_sys::esp_get_free_heap_size(), esp_idf_sys::esp_get_minimum_free_heap_size());
    }
}
