// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! macOS dependency alignment for the XMLSec build script.

use std::env;
use std::path::Path;
use std::process::Command;

use super::{emit_command_diagnostics, target_tool, BuildError, PkgInfo};

/// Bind the shim to the same libxml2 image that the discovered XMLSec uses.
///
/// Keg-only package metadata can advertise the SDK libxml2 while XMLSec itself
/// is linked to a package-manager libxml2. Crossing allocator-owned libxml2
/// objects between those ABIs causes memory corruption, so the actual dynamic
/// dependency is authoritative on macOS.
pub(super) fn align_libxml2_dependency(package: &mut PkgInfo) -> Result<(), BuildError> {
    let target = env::var("TARGET").unwrap_or_default();
    if !target.ends_with("apple-darwin") {
        return Ok(());
    }

    let xmlsec_library = package
        .lib_dirs
        .iter()
        .map(Path::new)
        .map(|directory| directory.join("libxmlsec1.dylib"))
        .find(|candidate| candidate.is_file())
        .ok_or(BuildError::XmlsecLibraryUnavailable)?;
    let output = Command::new(target_tool("OTOOL", "otool"))
        .arg("-L")
        .arg(xmlsec_library)
        .output()
        .map_err(|_| BuildError::DependencyInspectorUnavailable)?;
    if !output.status.success() {
        emit_command_diagnostics("dependency inspector", &output);
        return Err(BuildError::DependencyInspectionFailed);
    }

    let dependency_listing = String::from_utf8_lossy(&output.stdout);
    let dependency = dependency_listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(Path::new)
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("libxml2.") && name.ends_with(".dylib"))
        })
        .ok_or(BuildError::XmlsecLibxmlDependencyUnavailable)?;
    prepend_library_directory(package, dependency)?;
    prepend_include_directory(package, dependency)
}

fn prepend_library_directory(package: &mut PkgInfo, dependency: &Path) -> Result<(), BuildError> {
    let directory = dependency
        .parent()
        .and_then(Path::to_str)
        .ok_or(BuildError::NonUtf8Path)?
        .to_owned();
    package.lib_dirs.retain(|existing| existing != &directory);
    package.lib_dirs.insert(0, directory);
    Ok(())
}

fn prepend_include_directory(package: &mut PkgInfo, dependency: &Path) -> Result<(), BuildError> {
    let include_directory = dependency
        .parent()
        .and_then(Path::parent)
        .map(|prefix| prefix.join("include/libxml2"));
    if let Some(include_directory) = include_directory.filter(|path| path.is_dir()) {
        let include_directory = include_directory.to_str().ok_or(BuildError::NonUtf8Path)?;
        let flag = format!("-I{include_directory}");
        package.cflags.retain(|existing| existing != &flag);
        package.cflags.insert(0, flag);
    }
    Ok(())
}
