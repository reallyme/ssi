// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::print_stdout)]
//! Build script for the minimal libxmlsec C shim. It remains inert unless the
//! `xmlsec-ffi` feature is enabled, preserving portable workspace builds.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_DIAGNOSTIC_LINES: usize = 16;
const MAX_DIAGNOSTIC_CHARACTERS_PER_LINE: usize = 512;

mod build_macos;

/// Shared ABI limits and status codes, rendered into the generated C wrapper.
mod abi {
    include!("src/abi.rs");
}

fn main() {
    if let Err(error) = run() {
        error.emit();
        std::process::exit(1);
    }
}

fn run() -> Result<(), BuildError> {
    emit_rerun_inputs();

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
    for argument in pkg.link_args {
        println!("cargo:rustc-link-arg={argument}");
    }
    for argument in target_flags("LDFLAGS") {
        println!("cargo:rustc-link-arg={argument}");
    }

    Ok(())
}

fn emit_rerun_inputs() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../tsl-xmlsec/schemas/19612_xsd.xsd");
    println!("cargo:rerun-if-changed=../tsl-xmlsec/schemas/xml.xsd");
    println!("cargo:rerun-if-changed=../tsl-xmlsec/schemas/xmldsig-core-schema.xsd");
    println!("cargo:rerun-if-changed=src/wrapper.c.in");
    println!("cargo:rerun-if-changed=src/abi.rs");
    for variable in [
        "CC",
        "AR",
        "CFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "PKG_CONFIG",
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
        "PKG_CONFIG_SYSROOT_DIR",
        "OTOOL",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    if let Ok(target) = env::var("TARGET") {
        let underscored = target.replace('-', "_");
        for prefix in ["CC", "AR", "CFLAGS", "CPPFLAGS", "LDFLAGS", "PKG_CONFIG"] {
            println!("cargo:rerun-if-env-changed={prefix}_{target}");
            println!("cargo:rerun-if-env-changed={prefix}_{underscored}");
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BuildError {
    MissingOutDir,
    WriteWrapper,
    ReadSchema,
    XmlsecOpenSslPkgUnavailable,
    XmlsecVersionUnsupported,
    PkgConfigUnavailable,
    PkgConfigFailed,
    CompilerUnavailable,
    CompilerFailed,
    ArchiverUnavailable,
    ArchiverFailed,
    NonUtf8Path,
    XmlsecLibraryUnavailable,
    XmlsecLibxmlDependencyUnavailable,
    DependencyInspectorUnavailable,
    DependencyInspectionFailed,
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
            Self::XmlsecOpenSslPkgUnavailable => {
                "pkg-config could not find the required xmlsec1-openssl backend"
            }
            Self::XmlsecVersionUnsupported => {
                "xmlsec1-openssl 1.3.0 or newer is required for the configured signature profile"
            }
            Self::PkgConfigUnavailable => "failed to execute pkg-config",
            Self::PkgConfigFailed => {
                "pkg-config reported that the requested package is unavailable"
            }
            Self::CompilerUnavailable => "failed to execute the configured C compiler",
            Self::CompilerFailed => "the configured C compiler rejected the XMLSec wrapper",
            Self::ArchiverUnavailable => "failed to execute ar",
            Self::ArchiverFailed => "ar failed to create the XMLSec wrapper archive",
            Self::NonUtf8Path => "Cargo produced a non-UTF-8 build path",
            Self::XmlsecLibraryUnavailable => {
                "the xmlsec library reported by pkg-config could not be located"
            }
            Self::XmlsecLibxmlDependencyUnavailable => {
                "the xmlsec library does not expose a libxml2 dependency"
            }
            Self::DependencyInspectorUnavailable => {
                "the target dependency inspection tool is unavailable"
            }
            Self::DependencyInspectionFailed => {
                "the target dependency inspection tool rejected the xmlsec library"
            }
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
    Ok(WRAPPER_C
        .replace("/*__ABI_DEFINES__*/", &abi_defines())
        .replace("/*__SCHEMA_BYTES__*/", &arrays))
}

fn abi_defines() -> String {
    let limits = [
        ("MEID_XMLSEC_MAX_XML_BYTES", abi::MEID_XMLSEC_MAX_XML_BYTES),
        (
            "MEID_XMLSEC_MAX_TRUSTED_ROOTS",
            abi::MEID_XMLSEC_MAX_TRUSTED_ROOTS,
        ),
        (
            "MEID_XMLSEC_MAX_TRUSTED_ROOT_DER_BYTES",
            abi::MEID_XMLSEC_MAX_TRUSTED_ROOT_DER_BYTES,
        ),
        (
            "MEID_XMLSEC_MAX_SIGNER_DER_BYTES",
            abi::MEID_XMLSEC_MAX_SIGNER_DER_BYTES,
        ),
    ];
    let statuses = [
        ("MEID_XMLSEC_STATUS_OK", abi::MEID_XMLSEC_STATUS_OK),
        (
            "MEID_XMLSEC_STATUS_INVALID_ARGUMENT",
            abi::MEID_XMLSEC_STATUS_INVALID_ARGUMENT,
        ),
        (
            "MEID_XMLSEC_STATUS_INIT_FAILED",
            abi::MEID_XMLSEC_STATUS_INIT_FAILED,
        ),
        (
            "MEID_XMLSEC_STATUS_XML_PARSE_FAILED",
            abi::MEID_XMLSEC_STATUS_XML_PARSE_FAILED,
        ),
        (
            "MEID_XMLSEC_STATUS_MISSING_ROOT",
            abi::MEID_XMLSEC_STATUS_MISSING_ROOT,
        ),
        (
            "MEID_XMLSEC_STATUS_MISSING_SIGNATURE",
            abi::MEID_XMLSEC_STATUS_MISSING_SIGNATURE,
        ),
        (
            "MEID_XMLSEC_STATUS_KEYS_MANAGER_CREATE_FAILED",
            abi::MEID_XMLSEC_STATUS_KEYS_MANAGER_CREATE_FAILED,
        ),
        (
            "MEID_XMLSEC_STATUS_KEYS_MANAGER_INIT_FAILED",
            abi::MEID_XMLSEC_STATUS_KEYS_MANAGER_INIT_FAILED,
        ),
        (
            "MEID_XMLSEC_STATUS_TRUSTED_ROOT_LOAD_FAILED",
            abi::MEID_XMLSEC_STATUS_TRUSTED_ROOT_LOAD_FAILED,
        ),
        (
            "MEID_XMLSEC_STATUS_CONTEXT_SETUP_FAILED",
            abi::MEID_XMLSEC_STATUS_CONTEXT_SETUP_FAILED,
        ),
        (
            "MEID_XMLSEC_STATUS_SIGNATURE_INVALID",
            abi::MEID_XMLSEC_STATUS_SIGNATURE_INVALID,
        ),
        (
            "MEID_XMLSEC_STATUS_SCHEMA_INIT_FAILED",
            abi::MEID_XMLSEC_STATUS_SCHEMA_INIT_FAILED,
        ),
        (
            "MEID_XMLSEC_STATUS_SCHEMA_INVALID",
            abi::MEID_XMLSEC_STATUS_SCHEMA_INVALID,
        ),
        (
            "MEID_XMLSEC_STATUS_VERIFICATION_TIME_UNREPRESENTABLE",
            abi::MEID_XMLSEC_STATUS_VERIFICATION_TIME_UNREPRESENTABLE,
        ),
        (
            "MEID_XMLSEC_STATUS_POLICY_SETUP_FAILED",
            abi::MEID_XMLSEC_STATUS_POLICY_SETUP_FAILED,
        ),
    ];

    let mut defines = String::new();
    for (name, value) in limits {
        defines.push_str("#define ");
        defines.push_str(name);
        defines.push_str(" ((size_t)");
        defines.push_str(&value.to_string());
        defines.push_str("u)\n");
    }
    for (name, value) in statuses {
        defines.push_str("#define ");
        defines.push_str(name);
        defines.push_str(" (");
        defines.push_str(&value.to_string());
        defines.push_str(")\n");
    }
    defines
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
    link_args: Vec<String>,
}

fn probe_xmlsec_pkg() -> Result<PkgInfo, BuildError> {
    const XMLSEC_OPENSSL_PACKAGE: &str = "xmlsec1-openssl";
    const MINIMUM_XMLSEC_VERSION: &str = "1.3.0";

    if !pkg_config_succeeds(&["--exists", XMLSEC_OPENSSL_PACKAGE])? {
        return Err(BuildError::XmlsecOpenSslPkgUnavailable);
    }
    if !pkg_config_succeeds(&[
        "--atleast-version",
        MINIMUM_XMLSEC_VERSION,
        XMLSEC_OPENSSL_PACKAGE,
    ])? {
        return Err(BuildError::XmlsecVersionUnsupported);
    }

    let mut package = probe_pkg(XMLSEC_OPENSSL_PACKAGE)?;
    build_macos::align_libxml2_dependency(&mut package)?;
    Ok(package)
}

fn pkg_config_succeeds(args: &[&str]) -> Result<bool, BuildError> {
    let output = Command::new(target_tool("PKG_CONFIG", "pkg-config"))
        .args(args)
        .output()
        .map_err(|_| BuildError::PkgConfigUnavailable)?;
    if !output.status.success() {
        emit_command_diagnostics("pkg-config", &output);
    }
    Ok(output.status.success())
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
        link_args: Vec::new(),
    };

    let mut libs_out = Vec::new();

    for f in other {
        if let Some(v) = f.strip_prefix("-L") {
            pkg.lib_dirs.push(v.to_string());
        } else if let Some(v) = f.strip_prefix("-l") {
            libs_out.push(v.to_string());
        } else {
            pkg.link_args.push(f);
        }
    }
    pkg.libs = libs_out;

    Ok(pkg)
}

fn run_pkg_config(args: &[&str]) -> Result<Vec<String>, BuildError> {
    let out = Command::new(target_tool("PKG_CONFIG", "pkg-config"))
        .args(args)
        .output()
        .map_err(|_| BuildError::PkgConfigUnavailable)?;

    if !out.status.success() {
        emit_command_diagnostics("pkg-config", &out);
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

fn compile_wrapper(c_path: &Path, out_dir: &Path, pkg: &PkgInfo) -> Result<(), BuildError> {
    let cc = target_tool("CC", "cc");
    let ar = target_tool("AR", "ar");

    let obj = out_dir.join("meid_xmlsec_wrapper.o");
    let lib = out_dir.join("libmeid_xmlsec_wrapper.a");

    // Compile C into an object file.
    let mut cmd = Command::new(&cc);
    cmd.arg("-c")
        .arg(c_path)
        .arg("-o")
        .arg(&obj)
        .arg("-O2")
        .arg("-fPIC")
        .arg("-fstack-protector-strong")
        .arg("-fno-strict-overflow");

    for f in &pkg.cflags {
        cmd.arg(f);
    }
    for flag in target_flags("CPPFLAGS")
        .into_iter()
        .chain(target_flags("CFLAGS"))
    {
        cmd.arg(flag);
    }

    let output = cmd.output().map_err(|_| BuildError::CompilerUnavailable)?;
    if !output.status.success() {
        emit_command_diagnostics("C compiler", &output);
        return Err(BuildError::CompilerFailed);
    }

    let lib_path = lib.to_str().ok_or(BuildError::NonUtf8Path)?;
    let obj_path = obj.to_str().ok_or(BuildError::NonUtf8Path)?;

    // Archive into a static library.
    let output = Command::new(ar)
        .args(["crs", lib_path, obj_path])
        .output()
        .map_err(|_| BuildError::ArchiverUnavailable)?;
    if !output.status.success() {
        emit_command_diagnostics("archiver", &output);
        return Err(BuildError::ArchiverFailed);
    }

    Ok(())
}

fn emit_command_diagnostics(label: &str, output: &std::process::Output) {
    for (stream_name, bytes) in [("stderr", &output.stderr), ("stdout", &output.stdout)] {
        for line in String::from_utf8_lossy(bytes)
            .lines()
            .take(MAX_DIAGNOSTIC_LINES)
        {
            let sanitized: String = line
                .chars()
                .filter(|character| !character.is_control() || *character == '\t')
                .take(MAX_DIAGNOSTIC_CHARACTERS_PER_LINE)
                .collect();
            if !sanitized.is_empty() {
                println!("cargo:warning={label} {stream_name}: {sanitized}");
            }
        }
    }
}

fn target_tool(prefix: &str, fallback: &str) -> String {
    target_env(prefix)
        .or_else(|| env::var(prefix).ok())
        .unwrap_or_else(|| fallback.to_owned())
}

fn target_flags(prefix: &str) -> Vec<String> {
    target_env(prefix)
        .or_else(|| env::var(prefix).ok())
        .map(|flags| flags.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn target_env(prefix: &str) -> Option<String> {
    let target = env::var("TARGET").ok()?;
    env::var(format!("{prefix}_{target}"))
        .ok()
        .or_else(|| env::var(format!("{prefix}_{}", target.replace('-', "_"))).ok())
}

// Minimal C shim:
// - parses XML with libxml2
// - verifies the first ds:Signature node using xmlsec (OpenSSL backend)
// - returns the exact X.509 certificate selected as the verification key
// - returns MEID_XMLSEC_STATUS_OK on success and a negative status otherwise
//
// The Rust profile pre-pass remains the primary policy gate; the shim also
// restricts xmlsec to the same reference URIs and transforms as defense in depth.
const WRAPPER_C: &str = include_str!("src/wrapper.c.in");
