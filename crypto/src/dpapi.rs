use windows::Win32::Security::Cryptography::{
    CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
};
use windows::Win32::Foundation::{HLOCAL, LocalFree};

pub fn u_data(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut data_in = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB::default();

        let res = CryptUnprotectData(
            &mut data_in,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        );

        if res.is_ok() {
            let result = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();
            LocalFree(HLOCAL(data_out.pbData as *mut _));
            Ok(result)
        } else {
            Err(format!("CryptUnprotectData failed: {:x}", windows::core::Error::from_win32().code().0))
        }
    }
}
