use crate::{key, sign};

/// ActiveCertifiedKey wraps CertifiedKey and tracks OSCP and SCT state
/// in a single handshake.
pub(super) struct ActiveCertifiedKey<'a> {
    key: &'a sign::CertifiedKey,
    ocsp: Option<&'a [u8]>,
    sct_list: Option<&'a [u8]>,
}

impl<'a> ActiveCertifiedKey<'a> {
    pub(super) fn from_certified_key(key: &sign::CertifiedKey) -> ActiveCertifiedKey {
        ActiveCertifiedKey {
            key,
            ocsp: key.ocsp.as_deref(),
            sct_list: key.sct_list.as_deref(),
        }
    }

    /// Get the certificate chain
    #[inline]
    pub(super) fn get_cert(&self) -> &[key::Certificate] {
        &self.key.cert
    }

    /// Get the signing key
    #[inline]
    pub(super) fn get_key(&self) -> &dyn sign::SigningKey {
        &*self.key.key
    }

    #[inline]
    pub(super) fn get_ocsp(&self) -> Option<&[u8]> {
        self.ocsp
    }

    #[inline]
    pub(super) fn get_sct_list(&self) -> Option<&[u8]> {
        self.sct_list
    }
}

#[derive(Clone, Debug)]
/// Wrapping struct for the definition of an ALPN protocol to support alternate matchers
pub struct AlpnProtocol {
  protocol: Vec<u8>,
  matcher: AlpnProtocolMatcher
}

impl AlpnProtocol {
  /// Get raw bytes of ALPN protocol
  pub fn get_protocol(&self) -> &[u8] {
    &self.protocol
  }

  /// Match raw ALPN protocol against list provided in ClientHello message
  pub fn find_match(&self, client_protocols: &Vec<&[u8]>) -> Option<Vec<u8>> {
    self.matcher.find_match(self.protocol.as_slice(), client_protocols)
  }

  /// Constructor for protocols support prefix matching
  pub fn new_prefix_protocol(protocol: Vec<u8>) -> Self {
    Self {
      protocol,
      matcher: AlpnProtocolMatcher::Prefix
    }
  }

  /// Constructor for protocols only supporting the default, absolute match
  pub fn new_absolute_protocol(protocol: Vec<u8>) -> Self {
    Self {
      protocol,
      matcher: AlpnProtocolMatcher::Absolute
    }
  }
}

impl From<Vec<u8>> for AlpnProtocol {
  fn from(proto: Vec<u8>) -> Self {
    Self::new_absolute_protocol(proto)
  }
}

#[derive(Clone, Debug, PartialEq)]
/// Support protocol matching modes
enum AlpnProtocolMatcher {
  Absolute,
  Prefix
}

impl AlpnProtocolMatcher {
  /// Perform a match against the supported protocol and the offered protocols from the client
  fn find_match(&self, offered_protocol: &[u8], client_protocols: &Vec<&[u8]>) -> Option<Vec<u8>> {
    client_protocols
      .iter()
      .find(|&client_proto| match self {
        Self::Absolute => offered_protocol == *client_proto,
        Self::Prefix => client_proto.starts_with(offered_protocol)
      }).map(|&matched_protocol| matched_protocol.to_vec())
  }
}
