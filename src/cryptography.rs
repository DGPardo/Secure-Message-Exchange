use rand::rngs::OsRng;
use rsa::{sha2::Sha256, Oaep, RsaPrivateKey, RsaPublicKey};

pub fn generate_rsa_keypair(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

pub fn encrypt_message(public_key: &RsaPublicKey, data: &[u8]) -> Vec<u8> {
    let padding = Oaep::new::<Sha256>();
    public_key
        .encrypt(&mut OsRng, padding, data)
        .expect("failed to encrypt")
}

pub fn decrypt_message(
    private_key: &RsaPrivateKey,
    message: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let padding = Oaep::new::<Sha256>();
    Ok(private_key.decrypt(padding, &message)?)
}
