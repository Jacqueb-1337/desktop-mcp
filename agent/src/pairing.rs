//! Offline mutual host enrollment. This deliberately does not open a remote
//! listener, authorize MCP tools, or establish an encrypted network channel.
//! Its purpose is durable, authenticated device identity and revocable trust.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use uuid::Uuid;

const INVITE_SECONDS: u64 = 600;
const MAX_PEERS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    host_id: String,
    name: String,
    public_key: String,
    added_at: u64,
    // This is identity enrollment only. Remote invocation remains disabled.
    authorization: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    version: u32,
    private_key: String,
    peers: Vec<Peer>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    version: u32,
    invite_id: String,
    host_id: String,
    host_public_key: String,
    secret: String,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    version: u32,
    invite_id: String,
    host_public_key: String,
    peer_id: String,
    peer_public_key: String,
    peer_name: String,
    secret: String,
    nonce: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    version: u32,
    invite_id: String,
    host_id: String,
    host_public_key: String,
    peer_id: String,
    peer_public_key: String,
    nonce: String,
    signature: String,
}

struct LiveInvitation {
    invitation: Invitation,
}

struct PendingJoin {
    invite_id: String,
    host_public_key: String,
    nonce: String,
    created_at: u64,
}

pub struct Pairing {
    identity_path: PathBuf,
    signing_key: SigningKey,
    peers: Vec<Peer>,
    active: Option<LiveInvitation>,
    pending: Option<PendingJoin>,
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn bytes32(value: &str) -> Result<[u8; 32], String> {
    let decoded = hex::decode(value).map_err(|_| "INVALID_HEX".to_string())?;
    decoded.try_into().map_err(|_| "INVALID_32_BYTE_VALUE".into())
}

fn bytes64(value: &str) -> Result<[u8; 64], String> {
    let decoded = hex::decode(value).map_err(|_| "INVALID_HEX".to_string())?;
    decoded.try_into().map_err(|_| "INVALID_64_BYTE_VALUE".into())
}

fn verify_key(hex_key: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(&bytes32(hex_key)?)
        .map_err(|_| "INVALID_ED25519_KEY".into())
}

fn host_id(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    hex::encode(&digest[..16])
}

fn signed_frame(domain: &[u8], fields: &[&str]) -> Vec<u8> {
    let mut encoded = Vec::from(domain);
    for field in fields {
        encoded.extend_from_slice(&(field.len() as u32).to_be_bytes());
        encoded.extend_from_slice(field.as_bytes());
    }
    encoded
}

fn join_frame(v: &JoinRequest) -> Vec<u8> {
    signed_frame(
        b"desktop-mcp/offline-pair-request/v1\0",
        &[
            &v.invite_id, &v.host_public_key, &v.peer_id,
            &v.peer_public_key, &v.peer_name, &v.secret, &v.nonce,
        ],
    )
}

fn receipt_frame(v: &Receipt) -> Vec<u8> {
    signed_frame(
        b"desktop-mcp/offline-pair-receipt/v1\0",
        &[
            &v.invite_id, &v.host_id, &v.host_public_key,
            &v.peer_id, &v.peer_public_key, &v.nonce,
        ],
    )
}

fn constant_time_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut mismatch = 0u8;
    for (a, b) in a.bytes().zip(b.bytes()) {
        mismatch |= a ^ b;
    }
    mismatch == 0
}

fn valid_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed == name
        && !name.chars().any(char::is_control)
}

impl Pairing {
    pub fn open(dir: &Path) -> Result<Self, String> {
        if !dir.is_dir() {
            return Err("PAIRING_CONFIG_DIR_MISSING".into());
        }
        let path = dir.join("pairing-identity.json");
        let stored: StoredIdentity = if path.exists() {
            let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 128 * 1024 {
                return Err("INSECURE_PAIRING_IDENTITY_FILE".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if meta.permissions().mode() & 0o077 != 0
                    || meta.uid() != unsafe { libc::geteuid() }
                {
                    return Err("INSECURE_PAIRING_IDENTITY_PERMISSIONS".into());
                }
            }
            serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("CORRUPT_PAIRING_IDENTITY: {e}"))?
        } else {
            let key = SigningKey::generate(&mut OsRng);
            let value = StoredIdentity {
                version: 1,
                private_key: hex::encode(key.to_bytes()),
                peers: Vec::new(),
            };
            let payload = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| format!("IDENTITY_CREATE_FAILED: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|e| e.to_string())?;
            }
            f.write_all(&payload).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            value
        };
        if stored.version != 1 || stored.peers.len() > MAX_PEERS {
            return Err("INVALID_IDENTITY_VERSION_OR_PEERS".into());
        }
        let signing_key = SigningKey::from_bytes(&bytes32(&stored.private_key)?);
        for peer in &stored.peers {
            if host_id(verify_key(&peer.public_key)?.as_bytes()) != peer.host_id
                || !valid_name(&peer.name)
                || peer.authorization != "identity_only"
            {
                return Err("CORRUPT_TRUST_RECORD".into());
            }
        }
        Ok(Self {
            identity_path: path,
            signing_key,
            peers: stored.peers,
            active: None,
            pending: None,
        })
    }

    fn persist_peers(&self, peers: &[Peer]) -> Result<(), String> {
        let state = StoredIdentity {
            version: 1,
            private_key: hex::encode(self.signing_key.to_bytes()),
            peers: peers.to_vec(),
        };
        let bytes = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
        let dir = self.identity_path.parent().ok_or("IDENTITY_PATH_INVALID")?;
        let mut temp = NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        temp.write_all(&bytes).map_err(|e| e.to_string())?;
        temp.as_file().sync_all().map_err(|e| e.to_string())?;
        // Windows and Unix replace the destination atomically where supported.
        temp.persist(&self.identity_path).map_err(|e| e.error.to_string())?;
        Ok(())
    }

    fn public_key(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    fn id(&self) -> String {
        host_id(self.signing_key.verifying_key().as_bytes())
    }

    /// Sign only an authenticated TLS gateway presence challenge.
    pub fn sign_gateway_challenge(&self, nonce: &str) -> Result<Value, String> {
        if nonce.len() != 64 || bytes32(nonce).is_err() {
            return Err("INVALID_GATEWAY_NONCE".into());
        }
        let id = self.id();
        let key = self.public_key();
        let frame = signed_frame(b"desktop-mcp/gateway-presence/v1\0", &[nonce, &id, &key]);
        Ok(json!({
            "type": "authenticate", "version": 1,
            "host_id": id, "public_key": key,
            "signature": hex::encode(self.signing_key.sign(&frame).to_bytes())
        }))
    }

    pub fn identity(&self) -> Value {
        json!({
            "version": 1,
            "host_id": self.id(),
            "public_key": self.public_key(),
            "paired_peers": self.peers.len(),
            "transport_connected": false,
            "remote_tools_enabled": false,
            "remote_authorization": "none"
        })
    }

    pub fn list(&self) -> Value {
        json!({
            "identity":self.identity(),
            "peers":self.peers,
            "note":"Trust records only. No remote transport or MCP tool authorization exists."
        })
    }

    pub fn create_invitation(&mut self) -> Result<Value, String> {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let invite = Invitation {
            version: 1,
            invite_id: Uuid::new_v4().to_string(),
            host_id: self.id(),
            host_public_key: self.public_key(),
            secret: hex::encode(secret),
            expires_at: timestamp().saturating_add(INVITE_SECONDS),
        };
        self.active = Some(LiveInvitation {
            invitation: invite.clone(),
        });
        Ok(json!({
            "invitation": invite,
            "expires_in_seconds": INVITE_SECONDS,
            "one_time": true,
            "warning":"Confidential invitation. Exchange over a trusted channel. This does not enable remote access."
        }))
    }

    pub fn prepare_join(&mut self, invitation: &Value, name: &str) -> Result<Value, String> {
        if !valid_name(name) {
            return Err("INVALID_HOST_NAME".into());
        }
        let invitation: Invitation = serde_json::from_value(invitation.clone())
            .map_err(|e| format!("INVALID_INVITATION: {e}"))?;
        let now = timestamp();
        if invitation.version != 1
            || now > invitation.expires_at
            || invitation.expires_at > now.saturating_add(INVITE_SECONDS + 60)
            || invitation.host_id == self.id()
            || host_id(verify_key(&invitation.host_public_key)?.as_bytes()) != invitation.host_id
            || bytes32(&invitation.secret).is_err()
            || Uuid::parse_str(&invitation.invite_id).is_err()
        {
            return Err("INVALID_OR_EXPIRED_INVITATION".into());
        }
        let nonce = Uuid::new_v4().to_string();
        let mut request = JoinRequest {
            version: 1,
            invite_id: invitation.invite_id.clone(),
            host_public_key: invitation.host_public_key.clone(),
            peer_id: self.id(),
            peer_public_key: self.public_key(),
            peer_name: name.to_string(),
            secret: invitation.secret.clone(),
            nonce: nonce.clone(),
            signature: String::new(),
        };
        request.signature = hex::encode(self.signing_key.sign(&join_frame(&request)).to_bytes());
        self.pending = Some(PendingJoin {
            invite_id: invitation.invite_id,
            host_public_key: invitation.host_public_key,
            nonce,
            created_at: now,
        });
        Ok(json!({
            "join_request": request,
            "note":"Send this join request only to the inviting host. It includes a one-time secret."
        }))
    }

    pub fn accept_join(&mut self, request: &Value) -> Result<Value, String> {
        let request: JoinRequest = serde_json::from_value(request.clone())
            .map_err(|e| format!("INVALID_JOIN_REQUEST: {e}"))?;
        let active = self.active.as_ref().ok_or("INVITATION_NOT_ACTIVE")?;
        let invite = &active.invitation;
        if timestamp() > invite.expires_at {
            self.active = None;
            return Err("INVITATION_EXPIRED".into());
        }
        if request.version != 1
            || request.invite_id != invite.invite_id
            || request.host_public_key != invite.host_public_key
            || !constant_time_equal(&request.secret, &invite.secret)
            || request.peer_id == self.id()
            || !valid_name(&request.peer_name)
            || host_id(verify_key(&request.peer_public_key)?.as_bytes()) != request.peer_id
        {
            return Err("JOIN_REQUEST_REJECTED".into());
        }
        let key = verify_key(&request.peer_public_key)?;
        key.verify_strict(&join_frame(&request), &Signature::from_bytes(&bytes64(&request.signature)?))
            .map_err(|_| "INVALID_JOIN_SIGNATURE".to_string())?;
        if self.peers.iter().any(|p| p.host_id == request.peer_id) {
            return Err("PEER_ALREADY_TRUSTED".into());
        }
        if self.peers.len() >= MAX_PEERS {
            return Err("PEER_LIMIT_REACHED".into());
        }
        let mut receipt = Receipt {
            version: 1,
            invite_id: request.invite_id.clone(),
            host_id: self.id(),
            host_public_key: self.public_key(),
            peer_id: request.peer_id.clone(),
            peer_public_key: request.peer_public_key,
            nonce: request.nonce,
            signature: String::new(),
        };
        receipt.signature = hex::encode(self.signing_key.sign(&receipt_frame(&receipt)).to_bytes());
        let mut peers = self.peers.clone();
        peers.push(Peer {
            host_id: request.peer_id,
            public_key: receipt.peer_public_key.clone(),
            name: request.peer_name,
            added_at: timestamp(),
            authorization: "identity_only".into(),
        });
        self.persist_peers(&peers)?;
        self.peers = peers;
        self.active = None;
        Ok(json!({"receipt":receipt,"status":"enrolled",
            "remote_tools_enabled":false,"note":"Send the signed receipt back to the joining host."}))
    }

    pub fn finalize_join(&mut self, receipt: &Value, name: &str) -> Result<Value, String> {
        if !valid_name(name) {
            return Err("INVALID_HOST_NAME".into());
        }
        let receipt: Receipt = serde_json::from_value(receipt.clone())
            .map_err(|e| format!("INVALID_PAIRING_RECEIPT: {e}"))?;
        let pending = self.pending.as_ref().ok_or("NO_PENDING_JOIN")?;
        if timestamp() > pending.created_at.saturating_add(INVITE_SECONDS)
            || pending.invite_id != receipt.invite_id
            || pending.host_public_key != receipt.host_public_key
            || pending.nonce != receipt.nonce
            || receipt.version != 1
            || receipt.peer_id != self.id()
            || receipt.peer_public_key != self.public_key()
            || host_id(verify_key(&receipt.host_public_key)?.as_bytes()) != receipt.host_id
            || receipt.host_id == self.id()
        {
            return Err("PAIRING_RECEIPT_REJECTED".into());
        }
        verify_key(&receipt.host_public_key)?
            .verify_strict(&receipt_frame(&receipt), &Signature::from_bytes(&bytes64(&receipt.signature)?))
            .map_err(|_| "INVALID_RECEIPT_SIGNATURE".to_string())?;
        if self.peers.iter().any(|p| p.host_id == receipt.host_id) {
            return Err("PEER_ALREADY_TRUSTED".into());
        }
        if self.peers.len() >= MAX_PEERS {
            return Err("PEER_LIMIT_REACHED".into());
        }
        let mut peers = self.peers.clone();
        peers.push(Peer {
            host_id: receipt.host_id.clone(),
            name: name.to_string(),
            public_key: receipt.host_public_key,
            added_at: timestamp(),
            authorization: "identity_only".into(),
        });
        self.persist_peers(&peers)?;
        self.peers = peers;
        self.pending = None;
        Ok(json!({"status":"enrolled","peer_id":receipt.host_id,
            "remote_tools_enabled":false,"authorization":"identity_only"}))
    }

    pub fn revoke(&mut self, id: &str) -> Result<Value, String> {
        let peers: Vec<Peer> = self.peers.iter().filter(|p| p.host_id != id).cloned().collect();
        if peers.len() == self.peers.len() {
            return Err("PEER_NOT_FOUND".into());
        }
        self.persist_peers(&peers)?;
        self.peers = peers;
        Ok(json!({"status":"revoked","host_id":id,
            "remote_tools_enabled":false,
            "note":"Trust removed locally. A future gateway must propagate revocation."}))
    }

    pub fn cancel_invite(&mut self) -> Value {
        self.active = None;
        self.pending = None;
        json!({"status":"cancelled"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_host() -> (tempfile::TempDir, Pairing) {
        let temp = tempfile::tempdir().unwrap();
        let pair = Pairing::open(temp.path()).unwrap();
        (temp, pair)
    }

    #[test]
    fn mutual_signed_pairing_round_trip_persists_and_revokes() {
        let (a_temp, mut a) = new_host();
        let (b_temp, mut b) = new_host();
        assert_ne!(a.id(), b.id());
        let invite = a.create_invitation().unwrap()["invitation"].clone();
        let join = b.prepare_join(&invite, "Laptop").unwrap()["join_request"].clone();
        let result = a.accept_join(&join).unwrap();
        assert_eq!(result["remote_tools_enabled"], false);
        let receipt = result["receipt"].clone();
        assert_eq!(b.finalize_join(&receipt, "Desktop") .unwrap()["status"],"enrolled");
        assert_eq!(a.list()["peers"].as_array().unwrap().len(), 1);
        assert_eq!(b.list()["peers"].as_array().unwrap().len(), 1);
        assert!(a.accept_join(&join).is_err());
        assert!(b.finalize_join(&receipt, "Desktop").is_err());
        let id_b = b.id();
        assert_eq!(a.revoke(&id_b).unwrap()["status"], "revoked");
        assert_eq!(a.list()["peers"].as_array().unwrap().len(), 0);
        assert_eq!(Pairing::open(a_temp.path()).unwrap().list()["peers"].as_array().unwrap().len(),0);
        assert_eq!(Pairing::open(b_temp.path()).unwrap().list()["peers"].as_array().unwrap().len(),1);
        assert_eq!(Pairing::open(b_temp.path()).unwrap().id(), b.id());
    }

    #[test]
    fn rejects_modified_join_and_replayed_secret() {
        let (_a_dir, mut a) = new_host();
        let (_b_dir, mut b) = new_host();
        let invite = a.create_invitation().unwrap()["invitation"].clone();
        let mut join = b.prepare_join(&invite, "Laptop").unwrap()["join_request"].clone();
        join["peer_name"] = json!("Mallory");
        assert!(a.accept_join(&join).is_err());
        join["peer_name"] = json!("Laptop");
        join["secret"] = json!("0".repeat(64));
        assert!(a.accept_join(&join).is_err());
        assert_eq!(a.list()["peers"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn cannot_self_pair_or_accept_expired_invitation() {
        let (_temp, mut a) = new_host();
        let invite = a.create_invitation().unwrap()["invitation"].clone();
        assert!(a.prepare_join(&invite, "Self").is_err());
        let (_other, mut b) = new_host();
        let mut expired = invite;
        expired["expires_at"] = json!(timestamp() - 1);
        assert!(b.prepare_join(&expired,"Expired").is_err());
        assert_eq!(b.list()["peers"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn rejects_forged_receipt() {
        let (_a, mut a) = new_host();
        let (_b, mut b) = new_host();
        let invite = a.create_invitation().unwrap()["invitation"].clone();
        let join = b.prepare_join(&invite, "Laptop").unwrap()["join_request"].clone();
        let mut receipt = a.accept_join(&join).unwrap()["receipt"].clone();
        receipt["signature"] = json!("00".repeat(64));
        assert!(b.finalize_join(&receipt, "Desktop").is_err());
        assert_eq!(b.list()["peers"].as_array().unwrap().len(), 0);
    }
}
