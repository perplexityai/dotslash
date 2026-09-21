/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::io;
use std::io::BufRead;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;

use bzip2::read::BzDecoder;
use flate2::bufread::GzDecoder;
#[cfg(not(dotslash_internal))]
use liblzma::bufread::XzDecoder;
use tar::Archive;
#[cfg(not(dotslash_internal))]
use zip::ZipArchive;
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::util::fs_ctx;

#[derive(Copy, Clone)]
pub enum ArchiveType {
    Tar,
    #[cfg(not(dotslash_internal))]
    Bzip2,
    TarBzip2,
    #[cfg(not(dotslash_internal))]
    Gz,
    TarGz,
    #[cfg(not(dotslash_internal))]
    Xz,
    #[cfg(not(dotslash_internal))]
    TarXz,
    #[cfg(not(dotslash_internal))]
    Zstd,
    TarZstd,
    #[cfg(not(dotslash_internal))]
    Zip,
    Pkg,
}

/// Attempts to extract the tar/zip archive into the specified directory
/// or file.
///
/// To extract tars, this uses the tar crate (https://crates.io/crates/tar)
/// directly. Those who create compressed artifacts for DotSlash are
/// responsible for ensuring they can be decompressed with its version of tar.
pub fn unarchive<R>(reader: R, destination: &Path, archive_type: ArchiveType) -> io::Result<()>
where
    R: BufRead + Seek,
{
    match archive_type {
        ArchiveType::Tar => unpack_tar(reader, destination),

        #[cfg(not(dotslash_internal))]
        ArchiveType::Bzip2 => write_out(BzDecoder::new(reader), destination),
        ArchiveType::TarBzip2 => unpack_tar(BzDecoder::new(reader), destination),

        #[cfg(not(dotslash_internal))]
        ArchiveType::Gz => write_out(GzDecoder::new(reader), destination),
        ArchiveType::TarGz => unpack_tar(GzDecoder::new(reader), destination),

        #[cfg(not(dotslash_internal))]
        ArchiveType::Xz => write_out(XzDecoder::new(reader), destination),
        #[cfg(not(dotslash_internal))]
        ArchiveType::TarXz => unpack_tar(XzDecoder::new(reader), destination),

        #[cfg(not(dotslash_internal))]
        ArchiveType::Zstd => write_out(ZstdDecoder::with_buffer(reader)?, destination),
        ArchiveType::TarZstd => unpack_tar(ZstdDecoder::with_buffer(reader)?, destination),

        #[cfg(not(dotslash_internal))]
        ArchiveType::Zip => {
            let destination = fs_ctx::canonicalize(destination)?;
            let mut archive = ZipArchive::new(reader)?;
            archive.extract(destination)?;
            Ok(())
        }

        #[cfg(not(dotslash_internal))]
        ArchiveType::Pkg => {unpack_pkg(reader, destination)}
    }
}

#[cfg(not(dotslash_internal))]
fn write_out<R>(mut reader: R, destination_dir: &Path) -> io::Result<()>
where
    R: Read,
{
    let mut output_file = fs_ctx::file_create(destination_dir)?;
    io::copy(&mut reader, &mut output_file)?;
    Ok(())
}

#[cfg(not(dotslash_internal))]
fn unpack_pkg<R>(mut reader: R, destination: &Path) -> io::Result<()>
where
    R: BufRead + Seek,
{
    // PKG files are macOS installer packages
    // They can be either XAR archives or simple cpio/gzip archives
    let destination = fs_ctx::canonicalize(destination)?;
    
    // Try multiple extraction methods
    // First, check if it's a gzip-compressed cpio archive (common for simple PKGs)
    reader.seek(io::SeekFrom::Start(0))?;
    let mut magic = [0u8; 2];
    reader.read_exact(&mut magic)?;
    reader.seek(io::SeekFrom::Start(0))?;
    
    // Check for gzip magic number (0x1f, 0x8b)
    if magic[0] == 0x1f && magic[1] == 0x8b {
        // This is a gzipped file, likely containing a cpio archive
        // Extract it as a tar.gz for simplicity (many PKGs work this way)
        return unpack_tar(GzDecoder::new(reader), &destination);
    }
    
    // Check for XAR magic number (0x78, 0x61, 0x72, 0x21 = "xar!")
    let mut xar_magic = [0u8; 4];
    reader.read_exact(&mut xar_magic)?;
    reader.seek(io::SeekFrom::Start(0))?;
    
    if &xar_magic == b"xar!" {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            use tempfile::{NamedTempFile, TempDir};
            
            let mut temp_file = NamedTempFile::new()?;
            io::copy(&mut reader, &mut temp_file)?;
            temp_file.flush()?;

            let temp_dir_parent = TempDir::new()?;
            let temp_extract_path = temp_dir_parent.path().join("pkg_contents");
            
            let pkgutil_result = Command::new("pkgutil")
                .arg("--expand")
                .arg(temp_file.path())
                .arg(&temp_extract_path)
                .output()?;
            
            if !pkgutil_result.status.success() {
                let stderr = String::from_utf8_lossy(&pkgutil_result.stderr);
                return Err(io::Error::other(format!("pkgutil failed: {}", stderr)));
            }
            
            // Find the Payload file (may be nested in subdirectories)
            let find_output = Command::new("find")
                .arg(&temp_extract_path)
                .arg("-name")
                .arg("Payload")
                .arg("-type")
                .arg("f")
                .output()?;
            
            let payload_output = String::from_utf8_lossy(&find_output.stdout);
            let payload_path = payload_output
                .lines()
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| io::Error::other("No Payload file found in PKG"))?;
            
            // Extract the Payload (cpio.gz archive)
            let extract_cmd = format!(
                "cd '{}' && gzip -dc '{}' | cpio -idm 2>/dev/null",
                destination.display(),
                payload_path
            );
            
            let cpio_output = Command::new("sh")
                .arg("-c")
                .arg(&extract_cmd)
                .output()?;
            
            if !cpio_output.status.success() {
                return Err(io::Error::other("Failed to extract Payload from PKG"));
            }
            
            return Ok(());
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "PKG files are only supported on macOS",
            ));
        }
    }
    
    // If it's neither gzip nor XAR, don't handle it
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid PKG file: not a recognized PKG format (expected gzip or XAR)",
    ))
}

fn unpack_tar<R>(reader: R, destination_dir: &Path) -> io::Result<()>
where
    R: Read,
{
    // The destination dir is canonicalized for the benefit of Windows, but we
    // do it on all platforms for consistency of behavior.
    //
    // Windows has a path length limit of 255 chars. "Extended-length paths"[1]
    // are paths starting with `\\?\`. These are not subject to the length
    // limit, but have other issues: they cannot use forward slashes.
    //
    // `fs::canonicalize` will both prefix the path with `\\?\` and normalize
    // the slashes[2]. This is important because we don't know the depth of the
    // tarball file structure (so we need to avoid possible path length
    // limits), and we don't know if the destination path is mixing slashes.
    //
    // We only use extended-length paths here and not earlier because you
    // can't exec `.bat` files with `\\?\` (although `.exe` files are ok).
    //
    // We canonicalize for all platforms because `fs::canonicalize` can
    // error[3] and not everyone can test on Windows.
    //
    // [1] https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file#maxpath
    // [2] https://doc.rust-lang.org/std/fs/fn.canonicalize.html#platform-specific-behavior
    // [3] https://doc.rust-lang.org/std/fs/fn.canonicalize.html#errors

    let destination_dir = fs_ctx::canonicalize(destination_dir)?;

    let mut archive = Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.unpack(destination_dir)
}
