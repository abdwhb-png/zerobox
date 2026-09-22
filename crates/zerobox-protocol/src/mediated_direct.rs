use std::io;

pub const MAX_MEDIATED_DIRECT_PORTS: usize = 64;
pub const MEDIATED_DIRECT_LISTENER_MAGIC: &[u8; 4] = b"ZMD1";
pub const MEDIATED_DIRECT_ACK: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediatedDirectListenerManifest {
    pub ports: Vec<u16>,
}

impl MediatedDirectListenerManifest {
    pub fn new(mut ports: Vec<u16>) -> io::Result<Self> {
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() || ports.len() > MAX_MEDIATED_DIRECT_PORTS || ports.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mediated direct TCP requires 1 to 64 unique nonzero ports",
            ));
        }
        Ok(Self { ports })
    }

    pub fn descriptor_count(&self) -> usize {
        self.ports.len() + 2
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(6 + self.ports.len() * 2);
        encoded.extend_from_slice(MEDIATED_DIRECT_LISTENER_MAGIC);
        encoded.extend_from_slice(&(self.ports.len() as u16).to_be_bytes());
        for port in &self.ports {
            encoded.extend_from_slice(&port.to_be_bytes());
        }
        encoded
    }

    pub fn decode(encoded: &[u8]) -> io::Result<Self> {
        if encoded.len() < 6 || &encoded[..4] != MEDIATED_DIRECT_LISTENER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mediated listener manifest",
            ));
        }
        let count = usize::from(u16::from_be_bytes([encoded[4], encoded[5]]));
        if encoded.len() != 6 + count * 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mediated listener manifest length",
            ));
        }
        let ports = encoded[6..]
            .chunks_exact(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .collect();
        Self::new(ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_manifest_is_canonical_and_round_trips() {
        let manifest = MediatedDirectListenerManifest::new(vec![443, 80, 443]).unwrap();
        assert_eq!(manifest.ports, vec![80, 443]);
        assert_eq!(manifest.descriptor_count(), 4);
        assert_eq!(
            MediatedDirectListenerManifest::decode(&manifest.encode()).unwrap(),
            manifest
        );
    }

    #[test]
    fn listener_manifest_rejects_empty_zero_and_excessive_ports() {
        assert!(MediatedDirectListenerManifest::new(vec![]).is_err());
        assert!(MediatedDirectListenerManifest::new(vec![0]).is_err());
        assert!(MediatedDirectListenerManifest::new((1..=65).collect::<Vec<_>>()).is_err());
    }
}
