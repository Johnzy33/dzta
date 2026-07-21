#![no_std]
#![no_main]

use ark_bls12_381::{Fr, Bls12_381};
use core::panic::PanicInfo;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use zeroize::Zeroize;
use rand_chacha::ChaCha20Rng;
use ark_std::rand::SeedableRng;

use zkp_core_crypto::RoleVerificationCircuit;

#[derive(Zeroize)]
struct TeeCleartextContext {
    role_id: u64,
    nullifier: u64,
    nonce: u64,
    user_clearance: u64,
}

#[no_mangle]
pub extern "C" fn execute_tee_zkp_generation(
    role_id: u64,
    nullifier: u64,
    nonce: u64,
    commitment: u64,
    user_clearance: u64,
    required_clearance: u64,
    out_proof_ptr: *mut u8,
    out_proof_len: *mut usize,
) -> i32 {
    // 1. Ingest context inside stack-allocated zeroizing memory container
    let mut ctx = TeeCleartextContext {
        role_id,
        nullifier,
        nonce,
        user_clearance,
    };

    let secret_fr_role = Fr::from(ctx.role_id);
    let secret_fr_nullifier = Fr::from(ctx.nullifier);
    let secret_fr_clearance = Fr::from(ctx.user_clearance);

    let public_fr_nonce = Fr::from(ctx.nonce);
    let public_fr_commitment = Fr::from(commitment);
    let public_fr_required_clearance = Fr::from(required_clearance);

    // 2. Instantiate circuit variables
    let circuit = RoleVerificationCircuit {
        user_role_id: Some(secret_fr_role),
        secret_nullifier: Some(secret_fr_nullifier),
        user_clearance_level: Some(secret_fr_clearance),
        role_commitment: Some(public_fr_commitment),
        session_nonce: Some(public_fr_nonce),
        required_clearance_level: Some(public_fr_required_clearance),
    };

    // 3. Setup Parameter Generation
    // let mut rng = ark_std::test_rng();
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]); // or derive seed from TEE
    let (pk, _) = match Groth16::<Bls12_381>::circuit_specific_setup(
        RoleVerificationCircuit {
            user_role_id: None,
            secret_nullifier: None,
            user_clearance_level: None,
            role_commitment: None,
            session_nonce: None,
            required_clearance_level: None,
        },
        &mut rng,
        
    ) {
        Ok(keys) => keys,
        Err(_) => return -1,
    };

    // 4. Synthesize proof inside enclave memory spaces
    let proof = match Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng) {
        Ok(p) => p,
        Err(_) => return -2,
    };

    // 5. Serialize proof layout to buffer
    let mut serialized_buffer = [0u8; 512];
    let bytes_written = {
        let mut cursor = &mut serialized_buffer[..];
        if proof.serialize_uncompressed(&mut cursor).is_err() {
            return -3;
        }
        512 - cursor.len()
    };

    // Copy computed components down to external caller memory destinations safely
    unsafe {
        if out_proof_ptr.is_null() || out_proof_len.is_null() {
            return -4;
        }
        core::ptr::copy_nonoverlapping(serialized_buffer.as_ptr(), out_proof_ptr, bytes_written);
        *out_proof_len = bytes_written;
    }

    // 6. Memory Sanitization: Scrub stack registers containing private cleartext contexts
    ctx.zeroize();

    0 // Success status code
}

// #[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
