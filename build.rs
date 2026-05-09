fn main() {
    // Pass the GPGME symbol-version script so the produced .so exports
    // versioned symbols (GPGME_1.0 / GPGME_1.1) that libalpm expects.
    // Without this the linker emits an unversioned .so and glibc warns
    // "no version information available" at load time.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-Wl,--version-script={manifest}/lib/gpgme-sq.map");

    // Also set the ELF SONAME so ld.so finds the library as libgpgme.so.45.
    println!("cargo:rustc-link-arg=-Wl,-soname,libgpgme.so.45");
}
