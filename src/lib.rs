use std::str::FromStr;

use hex;
use nacl::sign::PUBLIC_KEY_LENGTH;
use rand::Rng;
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey, signature::Signature};
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GateResponseObject {
    pub domain: String,
    pub address: String,
    pub statement: String,
    pub version: String,
    pub nonce: String,
    pub chain_id: String,
    pub issued_at: String,
    pub resources: Vec<String>,
}

// TODO: Actually include proper error handling instead of
// returning default value

impl GateResponseObject {
    pub fn to_string(&self) -> String {
        let mut message = String::new();

        message.push_str(&format!(
            "{} wants you to sign in with your Solana account:\n",
            self.domain
        ));
        message.push_str(&self.address);
        message.push_str(&format!("\n\n{}", self.statement));

        let fields = vec![
            format!("Version: {}", self.version),
            format!("Chain ID: {}", self.chain_id),
            format!("Nonce: {}", self.nonce),
            format!("Issued At: {}", self.issued_at),
        ];

        let resources = self
            .resources
            .iter()
            .map(|r| format!("- {}", r))
            .collect::<Vec<_>>()
            .join("\n");

        let fields_with_resources = if !resources.is_empty() {
            let mut fields = fields;
            fields.push("Resources:".to_string());
            fields.push(resources);
            fields
        } else {
            fields
        };

        if !fields_with_resources.is_empty() {
            message.push_str(&format!("\n\n{}", fields_with_resources.join("\n")));
        }

        message
    }

    pub fn verify(&self, signature: &str) -> bool {
        let signature = match Signature::from_str(signature) {
            Ok(signature) => signature,
            Err(_) => return false,
        };

        let message = self.to_string();
        let messagebytes = message.as_bytes();

        let pk = match pubkey::Pubkey::from_str(&self.address) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let pkbytes = cast_to_pubkey(pk.as_ref()).unwrap();

        nacl::sign::verify(signature.as_ref(), messagebytes, pkbytes).unwrap_or_default()
    }
}

pub fn create_gate_message(domain: &str, address: &str) -> GateResponseObject {
    let version = "1".to_string();
    let chain_id = "mainnet".to_string();
    let nonce = generate_nonce();
    let created = time::OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let resources = vec![domain.to_string()];
    let statement = "Clicking Sign or Approve only means you have proved this wallet is owned by you. This request will not trigger any blockchain transaction or cost any gas fee.".to_string();

    let obj = GateResponseObject {
        domain: domain.to_string(),
        address: address.to_string(),
        statement,
        version,
        chain_id,
        nonce,
        issued_at: created.to_string(),
        resources,
    };

    obj
}

struct TryFromSliceError(());
impl std::fmt::Debug for TryFromSliceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TryFromSliceError").finish()
    }
}

fn cast_to_pubkey<T>(slice: &[T]) -> Result<&[T; PUBLIC_KEY_LENGTH], TryFromSliceError> {
    if slice.len() == PUBLIC_KEY_LENGTH {
        let ptr = slice.as_ptr() as *const [T; PUBLIC_KEY_LENGTH];
        unsafe { Ok(&*ptr) }
    } else {
        Err(TryFromSliceError(()))
    }
}

pub fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let n = rng.gen::<u32>();

    // Get bytes in little-endian format
    let bytes = n.to_le_bytes();

    hex::encode(bytes)
}
