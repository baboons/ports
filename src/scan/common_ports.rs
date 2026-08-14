//! Tier 2: the ports a dev machine is most likely to have something on.
//!
//! Checked before the full sweep so the common case — a handful of dev servers
//! on predictable ports — is described in a couple of hundred milliseconds
//! rather than after a six-second scan of all 65535.

/// Ports worth checking before falling back to the full range.
///
/// Insertion-ordered, not sorted: probing the dense dev ranges first means the
/// answers most people are waiting for arrive first.
pub fn common_ports() -> Vec<u16> {
    let mut ports = Vec::with_capacity(96);

    // The dense ranges every framework's default lives in.
    for start in [3000u16, 4000, 5000, 8000] {
        ports.extend(start..=start + 10);
    }
    ports.extend(8080u16..=8090);

    ports.extend([
        1313,  // hugo
        1420,  // tauri
        1717,  // roda / opennext
        2368,  // ghost
        3333,  // nest / adonis
        4200,  // angular
        4321,  // astro
        4443,  // https alt
        4567,  // sinatra
        4873,  // verdaccio
        5173,  // vite
        5174,  // vite, second instance
        5432,  // postgres
        5555,  // prisma studio
        6006,  // storybook
        6379,  // redis
        7000,  // airplay and friends
        7071,  // azure functions
        8888,  // jupyter
        8899,  //
        9000,  // php-fpm / minio / sonarqube
        9001,  //
        9090,  // prometheus
        9200,  // elasticsearch
        9229,  // node inspector
        9323,  // playwright report
        11434, // ollama
    ]);

    // Well-known web ports, including the two this tool's own proxy uses.
    ports.extend([80u16, 81, 88, 443, 591, 8008, 8443, 8834, 9443]);

    // 8008 is already covered by the 8000-8010 range; dedupe without sorting so
    // the ordering above survives.
    let mut seen = std::collections::HashSet::with_capacity(ports.len());
    ports.retain(|port| seen.insert(*port));
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_the_dense_dev_ranges_and_stays_deduped() {
        let ports = common_ports();

        for expected in [3000u16, 3010, 4000, 5173, 8080, 8090, 11434, 443] {
            assert!(ports.contains(&expected), "missing {expected}");
        }

        let unique: std::collections::HashSet<_> = ports.iter().collect();
        assert_eq!(unique.len(), ports.len(), "list contains duplicates");
    }

    #[test]
    fn probes_the_dev_ranges_before_the_well_known_ports() {
        // Ordering is the point of the list: 3000 should be answered long
        // before we get round to checking 443.
        let ports = common_ports();
        let index = |needle: u16| ports.iter().position(|p| *p == needle).unwrap();
        assert!(index(3000) < index(443));
        assert!(index(5173) < index(80));
    }
}
