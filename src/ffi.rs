use core::ffi::c_void;

use rand_core::{TryCryptoRng, TryRng};

use crate::{BluettiEncryption, Message, MessageType};

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

pub const BLUETTI_FFI_OK: i32 = 0;
pub const BLUETTI_FFI_ERR_NULL_POINTER: i32 = -1;
pub const BLUETTI_FFI_ERR_INVALID_INPUT: i32 = -2;
pub const BLUETTI_FFI_ERR_BUFFER_TOO_SMALL: i32 = -3;
pub const BLUETTI_FFI_ERR_OPERATION_FAILED: i32 = -4;
pub const BLUETTI_FFI_ERR_RNG_NOT_CONFIGURED: i32 = -5;
pub const BLUETTI_FFI_ERR_RNG_FAILED: i32 = -6;

pub type BluettiRandomCallback =
    unsafe extern "C" fn(user_data: *mut c_void, output: *mut u8, output_len: usize) -> i32;

#[repr(C)]
pub struct BluettiContext {
    inner: BluettiEncryption,
    random_callback: Option<BluettiRandomCallback>,
    random_user_data: *mut c_void,
}

impl BluettiContext {
    fn new() -> Self {
        Self {
            inner: BluettiEncryption::new(),
            random_callback: None,
            random_user_data: core::ptr::null_mut(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CallbackRngError {
    Failure,
}

impl core::fmt::Display for CallbackRngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Failure => f.write_str("random callback failed"),
        }
    }
}

impl core::error::Error for CallbackRngError {}

struct CallbackRng {
    callback: BluettiRandomCallback,
    user_data: *mut c_void,
}

impl TryRng for CallbackRng {
    type Error = CallbackRngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        // SAFETY: The callback and user_data pointer are provided by the C caller.
        // We pass a valid writable buffer pointer and its exact length.
        let rc = unsafe { (self.callback)(self.user_data, dst.as_mut_ptr(), dst.len()) };
        if rc == BLUETTI_FFI_OK {
            Ok(())
        } else {
            Err(CallbackRngError::Failure)
        }
    }
}

impl TryCryptoRng for CallbackRng {}

fn copy_to_output(data: &[u8], out_buf: *mut u8, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        return BLUETTI_FFI_ERR_NULL_POINTER;
    }

    // SAFETY: out_len is checked non-null above.
    let capacity = unsafe { *out_len };
    if data.len() > capacity {
        // SAFETY: out_len is checked non-null above.
        unsafe { *out_len = data.len() };
        return BLUETTI_FFI_ERR_BUFFER_TOO_SMALL;
    }

    if data.is_empty() {
        // SAFETY: out_len is checked non-null above.
        unsafe { *out_len = 0 };
        return BLUETTI_FFI_OK;
    }

    if out_buf.is_null() {
        return BLUETTI_FFI_ERR_NULL_POINTER;
    }

    // SAFETY: out_buf is non-null, and caller guarantees it points to a writable
    // region of at least `capacity` bytes. We already ensured `data.len() <= capacity`.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, data.len());
        *out_len = data.len();
    }

    BLUETTI_FFI_OK
}

fn validate_kex_message(data: &[u8], expected_type: MessageType) -> Result<Message<'_>, i32> {
    let message = Message::new(data);
    if !message.is_pre_key_exchange() {
        return Err(BLUETTI_FFI_ERR_INVALID_INPUT);
    }

    if message.message_type() != Some(expected_type) {
        return Err(BLUETTI_FFI_ERR_INVALID_INPUT);
    }

    if !message.verify_checksum() {
        return Err(BLUETTI_FFI_ERR_INVALID_INPUT);
    }

    Ok(message)
}

#[unsafe(no_mangle)]
pub extern "C" fn bluetti_init() -> *mut BluettiContext {
    let raw = unsafe { malloc(core::mem::size_of::<BluettiContext>()) as *mut BluettiContext };
    if raw.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: raw points to valid writable memory of size BluettiContext
    // returned by malloc above.
    unsafe {
        core::ptr::write(raw, BluettiContext::new());
    }

    raw
}

#[unsafe(no_mangle)]
pub extern "C" fn bluetti_set_random_callback(
    ctx: *mut BluettiContext,
    callback: Option<BluettiRandomCallback>,
    user_data: *mut c_void,
) -> i32 {
    if ctx.is_null() {
        return BLUETTI_FFI_ERR_NULL_POINTER;
    }

    // SAFETY: ctx is checked for null above and assumed to point to a valid
    // BluettiContext allocated by bluetti_init.
    let context = unsafe { &mut *ctx };
    context.random_callback = callback;
    context.random_user_data = user_data;

    BLUETTI_FFI_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn bluetti_handle_challenge(
    ctx: *mut BluettiContext,
    data: *const u8,
    len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if ctx.is_null() || data.is_null() {
        return BLUETTI_FFI_ERR_NULL_POINTER;
    }

    // SAFETY: pointers are checked for null above; caller provides valid memory.
    let context = unsafe { &mut *ctx };
    // SAFETY: caller guarantees data points to `len` readable bytes.
    let input = unsafe { core::slice::from_raw_parts(data, len) };

    let message = match validate_kex_message(input, MessageType::Challenge) {
        Ok(message) => message,
        Err(code) => return code,
    };

    match context.inner.handle_challenge(&message) {
        Ok(response) => copy_to_output(response.as_slice(), out_buf, out_len),
        Err(_) => BLUETTI_FFI_ERR_OPERATION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bluetti_handle_peer_pubkey(
    ctx: *mut BluettiContext,
    data: *const u8,
    len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if ctx.is_null() || data.is_null() {
        return BLUETTI_FFI_ERR_NULL_POINTER;
    }

    // SAFETY: pointers are checked for null above; caller provides valid memory.
    let context = unsafe { &mut *ctx };
    // SAFETY: caller guarantees data points to `len` readable bytes.
    let input = unsafe { core::slice::from_raw_parts(data, len) };

    let message = match validate_kex_message(input, MessageType::PeerPubkey) {
        Ok(message) => message,
        Err(code) => return code,
    };

    let callback = match context.random_callback {
        Some(callback) => callback,
        None => return BLUETTI_FFI_ERR_RNG_NOT_CONFIGURED,
    };

    let mut rng = CallbackRng {
        callback,
        user_data: context.random_user_data,
    };

    match context.inner.handle_peer_pubkey(&message, &mut rng) {
        Ok(response) => copy_to_output(response.as_slice(), out_buf, out_len),
        Err(_) => BLUETTI_FFI_ERR_RNG_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bluetti_handle_pubkey_accepted(
    ctx: *mut BluettiContext,
    data: *const u8,
    len: usize,
) -> i32 {
    if ctx.is_null() || data.is_null() {
        return BLUETTI_FFI_ERR_NULL_POINTER;
    }

    // SAFETY: pointers are checked for null above; caller provides valid memory.
    let context = unsafe { &mut *ctx };
    // SAFETY: caller guarantees data points to `len` readable bytes.
    let input = unsafe { core::slice::from_raw_parts(data, len) };

    let message = match validate_kex_message(input, MessageType::PubkeyAccepted) {
        Ok(message) => message,
        Err(code) => return code,
    };

    match context.inner.handle_pubkey_accepted(&message) {
        Ok(()) => BLUETTI_FFI_OK,
        Err(_) => BLUETTI_FFI_ERR_OPERATION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bluetti_is_ready(ctx: *const BluettiContext) -> bool {
    if ctx.is_null() {
        return false;
    }

    // SAFETY: ctx is checked for null above and assumed to point to a valid
    // BluettiContext allocated by bluetti_init.
    unsafe { (*ctx).inner.is_ready_for_commands() }
}

#[unsafe(no_mangle)]
pub extern "C" fn bluetti_free(ctx: *mut BluettiContext) {
    if ctx.is_null() {
        return;
    }

    // SAFETY: ctx must be a pointer previously returned by bluetti_init and not
    // yet freed. We drop the Rust value, then return raw storage to C allocator.
    unsafe {
        core::ptr::drop_in_place(ctx);
        free(ctx.cast());
    }
}
