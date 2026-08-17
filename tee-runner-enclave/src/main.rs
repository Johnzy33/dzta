// tee-runner-enclave/src/main.rs
#![no_std]
#![no_main]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use core::panic::PanicInfo;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

use zkp_core_crypto::RoleVerificationCircuit;

#[derive(Zeroize)]
struct TeeCleartextContext {
    user_clearance: u64,
    role_scalar: [u8; 32],
    nullifier: [u8; 32],
}

#[no_mangle]
pub extern "C" fn execute_tee_zkp_generation(
    user_clearance: u64,
    role_scalar_ptr: *const u8,
    nullifier_ptr: *const u8,
    required_clearance: u64,
    commitment_ptr: *const u8,
    pk_ptr: *const u8,
    pk_len: usize,
    out_proof_ptr: *mut u8,
    out_proof_len: *mut usize,
) -> i32 {
    // 1. Safety check for raw pointer inputs
    if role_scalar_ptr.is_null()
        || nullifier_ptr.is_null()
        || commitment_ptr.is_null()
        || pk_ptr.is_null()
        || out_proof_ptr.is_null()
        || out_proof_len.is_null()
    {
        return -4;
    }

    // Read 32-byte LE arrays safely from raw pointers
    let mut role_scalar_bytes = [0u8; 32];
    let mut nullifier_bytes = [0u8; 32];
    let mut commitment_bytes = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(role_scalar_ptr, role_scalar_bytes.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(nullifier_ptr, nullifier_bytes.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(commitment_ptr, commitment_bytes.as_mut_ptr(), 32);
    }

    // 2. Ingest context inside zeroizing stack memory
    let mut ctx = TeeCleartextContext {
        user_clearance,
        role_scalar: role_scalar_bytes,
        nullifier: nullifier_bytes,
    };

    // 3. Map raw inputs to scalar field elements (Fr)
    let secret_fr_clearance = Fr::from(ctx.user_clearance);
    let secret_fr_role_scalar = Fr::from_le_bytes_mod_order(&ctx.role_scalar);
    let secret_fr_nullifier = Fr::from_le_bytes_mod_order(&ctx.nullifier);

    let public_fr_required_clearance = Fr::from(required_clearance);
    let public_fr_commitment = Fr::from_le_bytes_mod_order(&commitment_bytes);

    // 4. Deserialize Proving Key from input buffer
    let pk_slice = unsafe { core::slice::from_raw_parts(pk_ptr, pk_len) };
    let proving_key = match ProvingKey::<Bls12_381>::deserialize_compressed(pk_slice) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };

    // 5. Instantiate circuit with populated parameters
    let circuit = RoleVerificationCircuit {
        user_clearance_level: Some(secret_fr_clearance),
        user_role_scalar: Some(secret_fr_role_scalar),
        secret_nullifier: Some(secret_fr_nullifier),
        required_clearance_level: Some(public_fr_required_clearance),
        public_commitment: Some(public_fr_commitment),
    };

    // 6. Seed isolated ChaCha20 RNG from nullifier
    let mut rng = ChaCha20Rng::from_seed(ctx.nullifier);

    // 7. Synthesize proof inside enclave memory space
    let proof = match Groth16::<Bls12_381>::prove(&proving_key, circuit, &mut rng) {
        Ok(p) => p,
        Err(_) => return -2,
    };

    // 8. Serialize compressed proof output to stack buffer
    let mut serialized_buffer = [0u8; 512];
    let bytes_written = {
        let mut cursor = &mut serialized_buffer[..];
        if proof.serialize_compressed(&mut cursor).is_err() {
            return -3;
        }
        512 - cursor.len()
    };

    // 9. Copy computed proof down to external caller buffer safely
    unsafe {
        core::ptr::copy_nonoverlapping(
            serialized_buffer.as_ptr(),
            out_proof_ptr,
            bytes_written,
        );
        *out_proof_len = bytes_written;
    }

    // 10. Memory Sanitization: Scrub stack registers containing private cleartext secrets
    ctx.zeroize();

    0 // Success status code
}

// #[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}