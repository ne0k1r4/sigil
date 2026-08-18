/// Tests for the new analysis features: Rich header parsing and TLS
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p.to_string_lossy().to_string()
}

// ── Rich header ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod rich_header {
    use super::*;
    use sigil::analyzer::{parse_rich_header, read_file};

    #[test]
    fn minimal_pe_has_no_rich_header() {
        // Our hand-crafted minimal PE has a 64-byte DOS stub with no Rich
        let data = read_file(&fixture("minimal.exe"), false).unwrap();
        let lfanew = 64u32; // matches the fixture generator
        assert!(parse_rich_header(&data, lfanew).is_none());
    }

    #[test]
    fn lfanew_below_minimum_returns_none() {
        let data = vec![0u8; 256];
        // lfanew < 0x80 must short-circuit to None regardless of content
        assert!(parse_rich_header(&data, 0x40).is_none());
    }

    #[test]
    fn lfanew_beyond_data_returns_none() {
        let data = vec![0u8; 16];
        assert!(parse_rich_header(&data, 0x200).is_none());
    }

    #[test]
    fn synthetic_rich_header_parses_and_hashes() {
        // Build a minimal buffer containing a valid Rich header structure:
        let key: u32 = 0xDEAD_BEEF;
        let mut data = vec![0u8; 0x200];

        let mut p = 0x80usize;
        // DanS marker
        write_u32(&mut data, p, 0x536E_6144 ^ key);
        p += 4;
        // 3 padding dwords
        for _ in 0..3 {
            write_u32(&mut data, p, key);
            p += 4;
        }
        // One entry: comp_id=0x00010002, count=5
        write_u32(&mut data, p, 0x0001_0002 ^ key);
        p += 4;
        write_u32(&mut data, p, 5 ^ key);
        p += 4;
        // "Rich" + key
        data[p..p + 4].copy_from_slice(b"Rich");
        write_u32(&mut data, p + 4, key);
        let _rich_end = p + 8;

        let lfanew = 0x180u32; // somewhere after our constructed region
        let rh = sigil::analyzer::parse_rich_header(&data, lfanew)
            .expect("expected a parsed rich header");
        assert_eq!(rh.entries.len(), 1);
        assert_eq!(rh.entries[0].comp_id, 0x0001_0002);
        assert_eq!(rh.entries[0].product_id, 0x0001);
        assert_eq!(rh.entries[0].build_number, 0x0002);
        assert_eq!(rh.entries[0].count, 5);
        assert_eq!(rh.hash.len(), 32); // md5 hex digest
    }

    fn write_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}

// ── TLS callback enumeration ─────────────────────────────────────────────────

#[cfg(test)]
mod tls_callbacks {
    use super::*;
    use goblin::Object;
    use sigil::analyzer::{analyze, parse_tls_callbacks, read_file};

    #[test]
    fn minimal_pe_has_no_tls_callbacks() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        assert!(info.tls_callbacks.is_empty());
    }

    #[test]
    fn no_tls_directory_returns_empty() {
        let data = read_file(&fixture("minimal.exe"), false).unwrap();
        let pe = match Object::parse(&data).unwrap() {
            Object::PE(pe) => pe,
            _ => panic!("expected PE"),
        };
        let lfanew = pe.header.dos_header.pe_pointer;
        let cbs = parse_tls_callbacks(&data, lfanew, pe.image_base as u64, &pe.sections);
        assert!(
            cbs.is_empty(),
            "minimal PE has no TLS directory — expected no callbacks"
        );
    }

    #[test]
    fn out_of_bounds_lfanew_does_not_panic() {
        let data = vec![0u8; 64];
        let cbs = parse_tls_callbacks(&data, 0x1000, 0x140000000, &[]);
        assert!(cbs.is_empty());
    }
}
