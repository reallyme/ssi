// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::print_stdout)]
//! Build script for the minimal libxmlsec C shim.
//!
//! The script is inert unless the `xmlsec-ffi` feature is enabled, which keeps
//! portable workspace builds independent of system libxmlsec availability.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if let Err(error) = run() {
        error.emit();
        std::process::exit(1);
    }
}

fn run() -> Result<(), BuildError> {
    // Only build/link the native wrapper when explicitly enabled by the parent crate.
    // This keeps the workspace buildable without system `libxmlsec1` installed.
    let xmlsec_ffi_enabled = env::var_os("CARGO_FEATURE_XMLSEC_FFI").is_some();
    if !xmlsec_ffi_enabled {
        return Ok(());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|_| BuildError::MissingOutDir)?);
    let c_path = out_dir.join("meid_xmlsec_wrapper.c");
    let wrapper = wrapper_with_pinned_schemas()?;
    fs::write(&c_path, wrapper).map_err(|_| BuildError::WriteWrapper)?;

    let pkg = probe_xmlsec_pkg()?;

    compile_wrapper(&c_path, &out_dir, &pkg)?;

    // Link the wrapper static lib.
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=meid_xmlsec_wrapper");

    // Link the xmlsec/libxml2/OpenSSL deps that pkg-config reports.
    for dir in pkg.lib_dirs {
        println!("cargo:rustc-link-search=native={dir}");
    }
    for lib in pkg.libs {
        println!("cargo:rustc-link-lib={lib}");
    }

    // Rebuild if this file changes.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../tsl-xmlsec/schemas/19612_xsd.xsd");
    println!("cargo:rerun-if-changed=../tsl-xmlsec/schemas/xml.xsd");
    println!("cargo:rerun-if-changed=../tsl-xmlsec/schemas/xmldsig-core-schema.xsd");
    println!("cargo:rerun-if-changed=src/wrapper.c.in");
    println!("cargo:rerun-if-env-changed=CC");

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum BuildError {
    MissingOutDir,
    WriteWrapper,
    ReadSchema,
    XmlsecPkgUnavailable,
    PkgConfigUnavailable,
    PkgConfigFailed,
    CompilerUnavailable,
    CompilerFailed,
    ArchiverUnavailable,
    ArchiverFailed,
    NonUtf8Path,
}

impl BuildError {
    fn emit(self) {
        println!(
            "cargo:warning=identity-trust-tsl-xmlsec-sys build failed: {}",
            self.message()
        );
    }

    fn message(self) -> &'static str {
        match self {
            Self::MissingOutDir => "Cargo did not provide OUT_DIR",
            Self::WriteWrapper => "failed to write the XMLSec C wrapper into OUT_DIR",
            Self::ReadSchema => "failed to read a pinned trusted-list schema",
            Self::XmlsecPkgUnavailable => "pkg-config could not find xmlsec1-openssl or xmlsec1",
            Self::PkgConfigUnavailable => "failed to execute pkg-config",
            Self::PkgConfigFailed => {
                "pkg-config reported that the requested package is unavailable"
            }
            Self::CompilerUnavailable => "failed to execute the configured C compiler",
            Self::CompilerFailed => "the configured C compiler rejected the XMLSec wrapper",
            Self::ArchiverUnavailable => "failed to execute ar",
            Self::ArchiverFailed => "ar failed to create the XMLSec wrapper archive",
            Self::NonUtf8Path => "Cargo produced a non-UTF-8 build path",
        }
    }
}

fn wrapper_with_pinned_schemas() -> Result<String, BuildError> {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(|_| BuildError::ReadSchema)?);
    let schema_dir = manifest_dir.join("../tsl-xmlsec/schemas");
    let etsi = fs::read(schema_dir.join("19612_xsd.xsd")).map_err(|_| BuildError::ReadSchema)?;
    let xml = fs::read(schema_dir.join("xml.xsd")).map_err(|_| BuildError::ReadSchema)?;
    let xmldsig =
        fs::read(schema_dir.join("xmldsig-core-schema.xsd")).map_err(|_| BuildError::ReadSchema)?;

    let mut arrays = String::new();
    append_c_byte_array(&mut arrays, "meid_etsi_tsl_xsd", &etsi);
    append_c_byte_array(&mut arrays, "meid_xml_namespace_xsd", &xml);
    append_c_byte_array(&mut arrays, "meid_xmldsig_xsd", &xmldsig);
    Ok(WRAPPER_C.replace("/*__SCHEMA_BYTES__*/", &arrays))
}

fn append_c_byte_array(output: &mut String, name: &str, bytes: &[u8]) {
    output.push_str("static const unsigned char ");
    output.push_str(name);
    output.push_str("[] = {");
    for byte in bytes {
        output.push_str(&byte.to_string());
        output.push(',');
    }
    output.push_str("0};\n");
    output.push_str("static const size_t ");
    output.push_str(name);
    output.push_str("_len = sizeof(");
    output.push_str(name);
    output.push_str(") - 1;\n");
}

struct PkgInfo {
    cflags: Vec<String>,
    lib_dirs: Vec<String>,
    libs: Vec<String>,
}

fn probe_xmlsec_pkg() -> Result<PkgInfo, BuildError> {
    // Homebrew on macOS commonly uses `xmlsec1-openssl`, while some distros use `xmlsec1`.
    let candidates = ["xmlsec1-openssl", "xmlsec1"];

    for name in candidates {
        if let Ok(pkg) = probe_pkg(name) {
            return Ok(pkg);
        }
    }

    Err(BuildError::XmlsecPkgUnavailable)
}

fn probe_pkg(name: &str) -> Result<PkgInfo, BuildError> {
    let cflags = run_pkg_config(&["--cflags", name])?;
    let libs = run_pkg_config(&["--libs", name])?;

    let (cflags, _other) = split_flags(&cflags);
    let (_ldflags, other) = split_flags(&libs);

    let mut pkg = PkgInfo {
        cflags,
        lib_dirs: Vec::new(),
        libs: Vec::new(),
    };

    let mut libs_out = Vec::new();

    for f in other {
        if let Some(v) = f.strip_prefix("-L") {
            pkg.lib_dirs.push(v.to_string());
        } else if let Some(v) = f.strip_prefix("-l") {
            libs_out.push(v.to_string());
        }
    }
    pkg.libs = libs_out;

    prefer_homebrew_libxml2_on_macos(&mut pkg);

    Ok(pkg)
}

fn run_pkg_config(args: &[&str]) -> Result<Vec<String>, BuildError> {
    let out = Command::new("pkg-config")
        .args(args)
        .output()
        .map_err(|_| BuildError::PkgConfigUnavailable)?;

    if !out.status.success() {
        return Err(BuildError::PkgConfigFailed);
    }

    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.split_whitespace().map(|x| x.to_string()).collect())
}

fn split_flags(flags: &[String]) -> (Vec<String>, Vec<String>) {
    // Treat all flags as "other" except include defines (-I, -D), which are forwarded to compilation.
    let mut cflags = Vec::new();
    let mut other = Vec::new();

    for f in flags {
        if f.starts_with("-I") || f.starts_with("-D") {
            cflags.push(f.clone());
        } else {
            other.push(f.clone());
        }
    }

    (cflags, other)
}

fn prefer_homebrew_libxml2_on_macos(pkg: &mut PkgInfo) {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let candidates = ["/opt/homebrew/opt/libxml2", "/usr/local/opt/libxml2"];
    for prefix in candidates {
        let lib_dir = Path::new(prefix).join("lib");
        let include_dir = Path::new(prefix).join("include/libxml2");
        let dylib = lib_dir.join("libxml2.dylib");

        if !dylib.exists() {
            continue;
        }

        let lib_dir = lib_dir.to_string_lossy().into_owned();
        if !pkg.lib_dirs.iter().any(|existing| existing == &lib_dir) {
            pkg.lib_dirs.insert(0, lib_dir);
        }

        if include_dir.exists() {
            let cflag = format!("-I{}", include_dir.display());
            if !pkg.cflags.iter().any(|existing| existing == &cflag) {
                pkg.cflags.insert(0, cflag);
            }
        }

        break;
    }
}

fn compile_wrapper(c_path: &Path, out_dir: &Path, pkg: &PkgInfo) -> Result<(), BuildError> {
    let cc = match env::var("CC") {
        Ok(value) => value,
        Err(_) => "cc".to_owned(),
    };

    let obj = out_dir.join("meid_xmlsec_wrapper.o");
    let lib = out_dir.join("libmeid_xmlsec_wrapper.a");

    // Compile C into an object file.
    let mut cmd = Command::new(&cc);
    cmd.arg("-c")
        .arg(c_path)
        .arg("-o")
        .arg(&obj)
        .arg("-O2")
        .arg("-fPIC");

    for f in &pkg.cflags {
        cmd.arg(f);
    }

    let out = cmd.output().map_err(|_| BuildError::CompilerUnavailable)?;
    if !out.status.success() {
        return Err(BuildError::CompilerFailed);
    }

    let lib_path = lib.to_str().ok_or(BuildError::NonUtf8Path)?;
    let obj_path = obj.to_str().ok_or(BuildError::NonUtf8Path)?;

    // Archive into a static library.
    let out = Command::new("ar")
        .args(["crs", lib_path, obj_path])
        .output()
        .map_err(|_| BuildError::ArchiverUnavailable)?;
    if !out.status.success() {
        return Err(BuildError::ArchiverFailed);
    }

    Ok(())
}

// Minimal C shim:
// - parses XML with libxml2
// - verifies the first ds:Signature node using xmlsec (OpenSSL backend)
// - returns the exact X.509 certificate selected as the verification key
// - returns 0 on success, non-zero on failure
//
// Intentionally minimal C shim; policy restrictions remain in Rust (same-doc only, no retrieval methods).
const WRAPPER_C: &str = include_str!("src/wrapper.c.in");
