use byteorder::{BigEndian, ByteOrder};
use log::debug;
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Encoding;

use crate::{kex::{KexAlgorithm, KexType}, msg};

use super::compute_keys_openssl;

pub struct EcdhNistP256KexType {}

impl KexType for EcdhNistP256KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        Box::new(EcdhNistPKex{
            group,
            local_private_key: None,
            local_public_key: None,
            shared_secret: None,
            digest: MessageDigest::sha256()
        }) as Box<dyn KexAlgorithm + Send>
    }
}

pub struct EcdhNistP384KexType {}

impl KexType for EcdhNistP384KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        Box::new(EcdhNistPKex{
            group,
            local_private_key: None,
            local_public_key: None,
            shared_secret: None,
            digest: MessageDigest::sha384()
        }) as Box<dyn KexAlgorithm + Send>
    }
}

pub struct EcdhNistP521KexType {}

impl KexType for EcdhNistP521KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
        Box::new(EcdhNistPKex{
            group,
            local_private_key: None,
            local_public_key: None,
            shared_secret: None,
            digest: MessageDigest::sha512()
        }) as Box<dyn KexAlgorithm + Send>
    }
}

pub struct EcdhNistPKex {
    group: EcGroup,
    local_private_key: Option<EcKey<Private>>,
    local_public_key: Option<EcPoint>,
    shared_secret: Option<Vec<u8>>,
    digest: MessageDigest
}

impl EcdhNistPKex {
    fn decode_public_key(&self, b: &[u8]) -> Result<PKey<Public>, crate::Error> {
        let mut ctx = BigNumContext::new()?;
        
        let remote_secret = EcPoint::from_bytes(&self.group, b, &mut ctx)?;
        let ec_key = EcKey::from_public_key(&self.group, &remote_secret)?;
        ec_key.check_key()?;

        let pkey = PKey::from_ec_key(ec_key)?;
        Ok(pkey)
    }

    fn generate_private_key(&mut self) -> Result<(), crate::Error> {
        let key = EcKey::generate(&self.group)?;
        self.local_private_key = Some(key);

        Ok(())
    }

    fn generate_public_key(&mut self) -> Result<(), crate::Error> {
        let private_key = self.local_private_key.as_ref().ok_or(crate::Error::Kex)?;
        let pubkey = private_key.public_key().to_owned(&self.group)?;
        self.local_public_key = Some(pubkey);

        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey: PKey<Public>) -> Result<(), crate::Error> {
        let local_ec_key = self.local_private_key.clone().ok_or(crate::Error::Kex)?;
        let local_private_key = PKey::from_ec_key(local_ec_key)?;
        let mut deriver = Deriver::new(&local_private_key)?;
        deriver.set_peer(&remote_pubkey)?;

        let shared_secret = deriver.derive_to_vec()?;
        self.shared_secret = Some(shared_secret);

        Ok(())
    }
}

impl std::fmt::Debug for EcdhNistPKex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{  }}"
        )
    }
}

impl KexAlgorithm for EcdhNistPKex {
    fn skip_exchange(&self) -> bool {
        false
    }

    // TODO: parse payload (init byute + 4 bytes len + public key)
    fn server_dh(&mut self, exchange: &mut crate::session::Exchange, payload: &[u8]) -> Result<(), crate::Error> {
        debug!("server_dh");
        
        let client_pubkey = {
            // parse pubkey from payload
            if payload.first() != Some(&msg::KEX_ECDH_INIT) {
                return Err(crate::Error::Inconsistent);
            }
    
            #[allow(clippy::indexing_slicing)] // length checked
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;

            let pubkey_bytes = payload.get(5..(5+pubkey_len)).ok_or(crate::Error::Inconsistent)?;
            self.decode_public_key(pubkey_bytes)?
        };

        // mint a server secret
        self.generate_private_key()?;
        self.generate_public_key()?;
        
        // fill exchange with compressed server pubkey
        let mut ctx = BigNumContext::new()?;
        let encoded_local_pubkey = self.local_public_key.as_ref().ok_or(crate::Error::Kex)?
            .to_bytes(&self.group, PointConversionForm::COMPRESSED, &mut ctx)?;
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&encoded_local_pubkey);

        // create shared secret from client pubkey and server secret
        self.compute_shared_secret(client_pubkey)?;

        Ok(())
    }

    fn client_dh(
        &mut self,
        client_ephemeral: &mut russh_cryptovec::CryptoVec,
        buf: &mut russh_cryptovec::CryptoVec,
    ) -> Result<(), crate::Error> {        
        self.generate_private_key()?;
        self.generate_public_key()?;

        // fill exchange with compressed client pubkey
        let mut ctx = BigNumContext::new()?;
        let encoded_pubkey = self.local_public_key.as_ref().ok_or(crate::Error::Kex)?
            .to_bytes(&self.group, PointConversionForm::COMPRESSED, &mut ctx)?;
        client_ephemeral.clear();
        client_ephemeral.extend(&encoded_pubkey);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&encoded_pubkey);

        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let peer_key = self.decode_public_key(remote_pubkey_)?;
        self.compute_shared_secret(peer_key)?;

        Ok(())
    }

    fn compute_exchange_hash(
        &self,
        key: &russh_cryptovec::CryptoVec,
        exchange: &crate::session::Exchange,
        buffer: &mut russh_cryptovec::CryptoVec,
    ) -> Result<russh_cryptovec::CryptoVec, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);

        buffer.extend(key);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_mpint(shared);
        }

        let hash = hash(self.digest, &buffer)?;
        let mut res = CryptoVec::new();
        res.extend(&hash);
        Ok(res)
    }

    fn compute_keys(
        &self,
        session_id: &russh_cryptovec::CryptoVec,
        exchange_hash: &russh_cryptovec::CryptoVec,
        cipher: crate::cipher::Name,
        remote_to_local_mac: crate::mac::Name,
        local_to_remote_mac: crate::mac::Name,
        is_server: bool,
    ) -> Result<crate::cipher::CipherPair, crate::Error> {
        compute_keys_openssl(
            self.shared_secret.as_deref(),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
            self.digest
        )
    }
}