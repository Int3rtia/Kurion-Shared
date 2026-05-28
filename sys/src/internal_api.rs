#[cfg(windows)]
use dinvk::syscall;
use std::ffi::c_void;
pub use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS, STATUS_BUFFER_TOO_SMALL, STATUS_BUFFER_OVERFLOW, STATUS_INFO_LENGTH_MISMATCH, STATUS_PENDING, HANDLE};

#[repr(C)]
pub struct UNICODE_STRING_SYSCALLS {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub length: u32,
    pub root_directory: HANDLE,
    pub object_name: *mut UNICODE_STRING_SYSCALLS,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

#[repr(C)]
pub struct CLIENT_ID {
    pub unique_process: HANDLE,
    pub unique_thread: HANDLE,
}

pub type KeyValueInformationClass = i32;
pub const KEY_VALUE_PARTIAL_INFORMATION_CLASS: KeyValueInformationClass = 2;

#[repr(C)]
pub struct KEY_VALUE_PARTIAL_INFORMATION {
    pub title_index: u32,
    pub type_: u32,
    pub data_length: u32,
}

#[repr(C)]
pub struct KEY_BASIC_INFORMATION {
    pub last_write_time: i64,
    pub title_index: u32,
    pub name_length: u32,
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub status: i32,
    pub information: usize,
}

#[repr(C)]
pub struct SYSTEM_MODULE {
    pub reserved: [usize; 2],
    pub image_base: *mut c_void,
    pub image_size: u32,
    pub flags: u32,
    pub load_order_index: u16,
    pub init_order_index: u16,
    pub load_count: u16,
    pub offset_to_file_name: u16,
    pub full_path_name: [u8; 256],
}

#[repr(C)]
pub struct SYSTEM_MODULE_INFORMATION {
    pub number_of_modules: u32,
}

#[repr(C)]
pub struct KEY_FULL_INFORMATION {
    pub last_write_time: i64,
    pub title_index: u32,
    pub class_offset: u32,
    pub class_length: u32,
    pub sub_keys: u32,
    pub max_name_len: u32,
    pub max_class_len: u32,
    pub values: u32,
    pub max_value_name_len: u32,
    pub max_value_data_len: u32,
}

#[cfg(windows)]
pub fn i_api(_verbose: bool) -> bool {
    true
}

#[cfg(not(windows))]
pub fn i_api(_verbose: bool) -> bool { true }

#[cfg(windows)]
pub fn i_object_attributes(
    p: &mut OBJECT_ATTRIBUTES,
    n: &mut UNICODE_STRING_SYSCALLS,
    a: u32,
    r: *mut c_void,
    s: *mut c_void,
) {
    p.length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    p.root_directory = HANDLE(r as *mut c_void);
    p.object_name = n;
    p.attributes = a;
    p.security_descriptor = s;
    p.security_quality_of_service = std::ptr::null_mut();
}

#[cfg(windows)]
pub unsafe fn n_close_syscall(handle: *mut c_void) -> NTSTATUS {
    let status = syscall!("NtClose", handle);
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_open_key_syscall(
    key_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let status = syscall!("NtOpenKey", key_handle, desired_access, object_attributes);
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_query_value_key_syscall(
    key_handle: *mut c_void,
    value_name: *mut UNICODE_STRING_SYSCALLS,
    key_value_information_class: KeyValueInformationClass,
    key_value_information: *mut c_void,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtQueryValueKey",
        key_handle,
        value_name,
        key_value_information_class,
        key_value_information,
        length,
        result_length
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_enumerate_key_syscall(
    key_handle: *mut c_void,
    index: u32,
    key_information_class: i32,
    key_information: *mut c_void,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtEnumerateKey",
        key_handle,
        index,
        key_information_class,
        key_information,
        length,
        result_length
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_allocate_virtual_memory_syscall(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtAllocateVirtualMemory",
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_write_virtual_memory_syscall(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *mut c_void,
    number_of_bytes_to_write: usize,
    number_of_bytes_written: *mut usize,
) -> NTSTATUS {
    let status = syscall!(
        "NtWriteVirtualMemory",
        process_handle,
        base_address,
        buffer,
        number_of_bytes_to_write,
        number_of_bytes_written
    );
     match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_create_thread_ex_syscall(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut c_void,
    process_handle: HANDLE,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut c_void,
) -> NTSTATUS {
    let status = syscall!(
        "NtCreateThreadEx",
        thread_handle,
        desired_access,
        object_attributes,
        process_handle,
        start_routine,
        argument,
        create_flags,
        zero_bits,
        stack_size,
        maximum_stack_size,
        attribute_list
    );
     match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_wait_for_single_object_syscall(
    handle: HANDLE,
    alertable: bool,
    timeout: *mut i64,
) -> NTSTATUS {
     let status = syscall!(
        "NtWaitForSingleObject",
        handle,
        alertable as u32,
        timeout
    );
     match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_open_process_syscall(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut c_void,
) -> NTSTATUS {
    let status = syscall!(
        "NtOpenProcess",
        process_handle,
        desired_access,
        object_attributes,
        client_id
    );
     match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_read_virtual_memory_syscall(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *mut c_void,
    number_of_bytes_to_read: usize,
    number_of_bytes_read: *mut usize,
) -> NTSTATUS {
    let status = syscall!(
        "NtReadVirtualMemory",
        process_handle,
        base_address,
        buffer,
        number_of_bytes_to_read,
        number_of_bytes_read
    );
     match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_query_virtual_memory_syscall(
    process_handle: HANDLE,
    base_address: *mut c_void,
    memory_information_class: u32,
    memory_information: *mut c_void,
    memory_information_length: usize,
    return_length: *mut usize,
) -> NTSTATUS {
    let status = syscall!(
        "NtQueryVirtualMemory",
        process_handle,
        base_address,
        memory_information_class,
        memory_information,
        memory_information_length,
        return_length
    );
     match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_protect_virtual_memory_syscall(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtProtectVirtualMemory",
        process_handle,
        base_address,
        region_size,
        new_protect,
        old_protect
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_query_system_information_syscall(
    system_information_class: u32,
    system_information: *mut c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtQuerySystemInformation",
        system_information_class,
        system_information,
        system_information_length,
        return_length
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_free_virtual_memory_syscall(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    free_type: u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtFreeVirtualMemory",
        process_handle,
        base_address,
        region_size,
        free_type
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_open_file_syscall(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtOpenFile",
        file_handle,
        desired_access,
        object_attributes,
        io_status_block,
        share_access,
        open_options
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_device_io_control_file_syscall(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    io_control_code: u32,
    input_buffer: *mut c_void,
    input_buffer_length: u32,
    output_buffer: *mut c_void,
    output_buffer_length: u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtDeviceIoControlFile",
        file_handle,
        event,
        apc_routine,
        apc_context,
        io_status_block,
        io_control_code,
        input_buffer,
        input_buffer_length,
        output_buffer,
        output_buffer_length
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_open_mutant_syscall(
    mutant_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let status = syscall!(
        "NtOpenMutant",
        mutant_handle,
        desired_access,
        object_attributes
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_open_directory_object_syscall(
    directory_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let status = syscall!(
        "NtOpenDirectoryObject",
        directory_handle,
        desired_access,
        object_attributes
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_query_directory_object_syscall(
    directory_handle: HANDLE,
    buffer: *mut c_void,
    length: u32,
    return_single_entry: u8,
    restart_scan: u8,
    context: *mut u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtQueryDirectoryObject",
        directory_handle,
        buffer,
        length,
        return_single_entry as u32,
        restart_scan as u32,
        context,
        return_length
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_query_information_thread_syscall(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: *mut c_void,
    thread_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtQueryInformationThread",
        thread_handle,
        thread_information_class,
        thread_information,
        thread_information_length,
        return_length
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_set_information_thread_syscall(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: *mut c_void,
    thread_information_length: u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtSetInformationThread",
        thread_handle,
        thread_information_class,
        thread_information,
        thread_information_length
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(windows)]
pub unsafe fn n_query_key_syscall(
    key_handle: *mut c_void,
    key_information_class: i32,
    key_information: *mut c_void,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    let status = syscall!(
        "NtQueryKey",
        key_handle,
        key_information_class,
        key_information,
        length,
        result_length
    );
    match status {
        Some(s) => NTSTATUS(s),
        None => NTSTATUS(-1),
    }
}

#[cfg(not(windows))]
pub unsafe fn n_close_syscall(_h: *mut c_void) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_open_key_syscall(_k: *mut *mut c_void, _d: u32, _o: *mut OBJECT_ATTRIBUTES) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_query_value_key_syscall(_k: *mut c_void, _v: *mut UNICODE_STRING_SYSCALLS, _c: KeyValueInformationClass, _i: *mut c_void, _l: u32, _r: *mut u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_allocate_virtual_memory_syscall(_h: HANDLE, _b: *mut *mut c_void, _z: usize, _r: *mut usize, _a: u32, _p: u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_write_virtual_memory_syscall(_h: HANDLE, _b: *mut c_void, _bf: *mut c_void, _n: usize, _nw: *mut usize) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_create_thread_ex_syscall(_t: *mut HANDLE, _d: u32, _o: *mut c_void, _p: HANDLE, _s: *mut c_void, _a: *mut c_void, _c: u32, _z: usize, _ss: usize, _ms: usize, _al: *mut c_void) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_wait_for_single_object_syscall(_h: HANDLE, _a: bool, _t: *mut i64) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub fn i_object_attributes(_p: &mut OBJECT_ATTRIBUTES, _n: &mut UNICODE_STRING_SYSCALLS, _a: u32, _r: *mut c_void, _s: *mut c_void) {}

#[cfg(not(windows))]
pub unsafe fn n_open_process_syscall(_h: *mut HANDLE, _d: u32, _o: *mut OBJECT_ATTRIBUTES, _c: *mut c_void) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_read_virtual_memory_syscall(_h: HANDLE, _b: *mut c_void, _buf: *mut c_void, _n: usize, _nr: *mut usize) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_query_virtual_memory_syscall(_h: HANDLE, _b: *mut c_void, _c: u32, _i: *mut c_void, _l: usize, _r: *mut usize) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_protect_virtual_memory_syscall(_h: HANDLE, _b: *mut *mut c_void, _r: *mut usize, _n: u32, _o: *mut u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_enumerate_key_syscall(_h: *mut c_void, _i: u32, _c: i32, _k: *mut c_void, _l: u32, _r: *mut u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_query_system_information_syscall(_c: u32, _i: *mut c_void, _l: u32, _r: *mut u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_free_virtual_memory_syscall(_h: HANDLE, _b: *mut *mut c_void, _s: *mut usize, _f: u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_open_file_syscall(_h: *mut HANDLE, _a: u32, _o: *mut OBJECT_ATTRIBUTES, _i: *mut IO_STATUS_BLOCK, _s: u32, _op: u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_device_io_control_file_syscall(_h: HANDLE, _e: HANDLE, _ar: *mut c_void, _ac: *mut c_void, _i: *mut IO_STATUS_BLOCK, _io: u32, _ib: *mut c_void, _il: u32, _ob: *mut c_void, _ol: u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_open_mutant_syscall(_h: *mut HANDLE, _a: u32, _o: *mut OBJECT_ATTRIBUTES) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_open_directory_object_syscall(_h: *mut HANDLE, _a: u32, _o: *mut OBJECT_ATTRIBUTES) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_query_directory_object_syscall(_h: HANDLE, _b: *mut c_void, _l: u32, _s: u8, _f: u8, _c: *mut u32, _r: *mut u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_query_information_thread_syscall(_h: HANDLE, _c: u32, _i: *mut c_void, _l: u32, _r: *mut u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_set_information_thread_syscall(_h: HANDLE, _c: u32, _i: *mut c_void, _l: u32) -> NTSTATUS { STATUS_SUCCESS }
#[cfg(not(windows))]
pub unsafe fn n_query_key_syscall(_h: *mut c_void, _c: i32, _i: *mut c_void, _l: u32, _r: *mut u32) -> NTSTATUS { STATUS_SUCCESS }
