extern crate cc;
extern crate pkg_config;
#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBZ_SYS_STATIC");
    println!("cargo:rerun-if-changed=build.rs");
    let host = env::var("HOST").unwrap();
    let target = env::var("TARGET").unwrap();

    let host_and_target_contain = |s| host.contains(s) && target.contains(s);

    let want_ng = cfg!(feature = "zlib-ng") && !cfg!(feature = "stock-zlib");

    if want_ng && target != "wasm32-unknown-unknown" {
        return build_zlib_ng(&target);
    }

    // Don't run pkg-config if we're linking statically (we'll build below) and
    // also don't run pkg-config on macOS/FreeBSD/DragonFly. That'll end up printing
    // `-L /usr/lib` which wreaks havoc with linking to an OpenSSL in /usr/local/lib
    // (Homebrew, Ports, etc.)
    let want_static =
        cfg!(feature = "static") || env::var("LIBZ_SYS_STATIC").unwrap_or(String::new()) == "1";
    if !want_static &&
       !target.contains("msvc") && // pkg-config just never works here
       !(host_and_target_contain("apple") ||
         host_and_target_contain("freebsd") ||
         host_and_target_contain("dragonfly"))
    {
        // Don't print system lib dirs to cargo since this interferes with other
        // packages adding non-system search paths to link against libraries
        // that are also found in a system-wide lib dir.
        let zlib = pkg_config::Config::new()
            .cargo_metadata(true)
            .print_system_libs(false)
            .probe("zlib");
        if zlib.is_ok() {
            return;
        }
    }

    if target.contains("msvc") {
        if try_vcpkg() {
            return;
        }
    }

    // All android compilers should come with libz by default, so let's just use
    // the one already there. Likewise, Haiku always ships with libz, so we can
    // link to it even when cross-compiling.
    if target.contains("android") || target.contains("haiku") {
        println!("cargo:rustc-link-lib=z");
        return;
    }

    let mut cfg = cc::Build::new();

    // Situations where we build unconditionally.
    //
    // MSVC basically never has it preinstalled, MinGW picks up a bunch of weird
    // paths we don't like, `want_static` may force us, cross compiling almost
    // never has a prebuilt version, and musl is almost always static.
    if target.contains("msvc")
        || target.contains("pc-windows-gnu")
        || want_static
        || target != host
    {
        return build_zlib(&mut cfg, &target);
    }

    // If we've gotten this far we're probably a pretty standard platform.
    // Almost all platforms here ship libz by default, but some don't have
    // pkg-config files that we would find above.
    //
    // In any case test if zlib is actually installed and if so we link to it,
    // otherwise continue below to build things.
    if zlib_installed(&mut cfg) {
        println!("cargo:rustc-link-lib=z");
        return;
    }

    build_zlib(&mut cfg, &target)
}

fn build_zlib(cfg: &mut cc::Build, target: &str) {
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let lib = dst.join("lib");

    cfg.warnings(false).out_dir(&lib).include("src/zlib");

    cfg.file("src/zlib/adler32.c")
        .file("src/zlib/compress.c")
        .file("src/zlib/crc32.c")
        .file("src/zlib/deflate.c")
        .file("src/zlib/infback.c")
        .file("src/zlib/inffast.c")
        .file("src/zlib/inflate.c")
        .file("src/zlib/inftrees.c")
        .file("src/zlib/trees.c")
        .file("src/zlib/uncompr.c")
        .file("src/zlib/zutil.c");

    if !cfg!(feature = "libc") || target.starts_with("wasm32") {
        cfg.define("Z_SOLO", None);
    } else {
        cfg.file("src/zlib/gzclose.c")
            .file("src/zlib/gzlib.c")
            .file("src/zlib/gzread.c")
            .file("src/zlib/gzwrite.c");
    }

    if !target.contains("windows") {
        cfg.define("STDC", None);
        cfg.define("_LARGEFILE64_SOURCE", None);
        cfg.define("_POSIX_SOURCE", None);
        cfg.flag("-fvisibility=hidden");
    }
    if target.contains("apple") {
        cfg.define("_C99_SOURCE", None);
    }
    if target.contains("solaris") {
        cfg.define("_XOPEN_SOURCE", "700");
    }

    cfg.compile("z");

    fs::create_dir_all(dst.join("include")).unwrap();
    fs::copy("src/zlib/zlib.h", dst.join("include/zlib.h")).unwrap();
    fs::copy("src/zlib/zconf.h", dst.join("include/zconf.h")).unwrap();

    fs::create_dir_all(lib.join("pkgconfig")).unwrap();
    fs::write(
        lib.join("pkgconfig/zlib.pc"),
        fs::read_to_string("src/zlib/zlib.pc.in")
            .unwrap()
            .replace("@prefix@", dst.to_str().unwrap()),
    )
    .unwrap();

    println!("cargo:root={}", dst.to_str().unwrap());
    println!("cargo:rustc-link-search=native={}", lib.to_str().unwrap());
    println!("cargo:include={}/include", dst.to_str().unwrap());
}

#[cfg(not(feature = "zlib-ng"))]
fn build_zlib_ng(_target: &str) {}

#[cfg(feature = "zlib-ng")]
fn build_zlib_ng(target: &str) {
    let install_dir = cmake::Config::new("src/zlib-ng")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("ZLIB_COMPAT", "ON")
        .define("WITH_GZFILEOP", "ON")
        .build();
    let includedir = install_dir.join("include");
    let libdir = install_dir.join("lib");
    println!(
        "cargo:rustc-link-search=native={}",
        libdir.to_str().unwrap()
    );
    let libname = if target.contains("windows") {
        if target.contains("msvc") && env::var("OPT_LEVEL").unwrap() == "0" {
            "zlibd"
        } else {
            "zlib"
        }
    } else {
        "z"
    };
    println!("cargo:rustc-link-lib=static={}", libname);
    println!("cargo:root={}", install_dir.to_str().unwrap());
    println!("cargo:include={}", includedir.to_str().unwrap());
}

#[cfg(not(target_env = "msvc"))]
fn try_vcpkg() -> bool {
    false
}

#[cfg(target_env = "msvc")]
fn try_vcpkg() -> bool {
    // see if there is a vcpkg tree with zlib installed
    match vcpkg::Config::new()
        .emit_includes(true)
        .lib_names("zlib", "zlib1")
        .probe("zlib")
    {
        Ok(_) => true,
        Err(e) => {
            println!("note, vcpkg did not find zlib: {}", e);
            false
        }
    }
}

fn zlib_installed(cfg: &mut cc::Build) -> bool {
    let compiler = cfg.get_compiler();
    let mut cmd = Command::new(compiler.path());
    cmd.arg("src/smoke.c").arg("-o").arg("/dev/null").arg("-lz");

    println!("running {:?}", cmd);
    if let Ok(status) = cmd.status() {
        if status.success() {
            return true;
        }
    }

    false
}
