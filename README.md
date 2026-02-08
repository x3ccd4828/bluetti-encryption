# bluetti-encryption

`no_std` Bluetti BLE encryption protocol implementation.

## Build static library for ESPHome

This crate defaults to `rlib` for normal Rust dependency use (for example Embassy projects). For ESPHome C FFI
integration, build a `staticlib` with the `c_ffi` feature enabled.

Run from this directory (`bluetti-encryption`):

```bash
cargo +esp rustc -Z build-std=core,alloc --release --features c_ffi --target xtensa-esp32-none-elf --lib --crate-type staticlib
```

Expected output:

```text
bluetti-encryption/target/xtensa-esp32-none-elf/release/libbluetti_encryption.a
```
