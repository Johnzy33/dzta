// dzta-e2e-tests/src/fixtures.rs

pub fn create_mock_sgx_quote(mrenclave_hex: &str, mrsigner_hex: &str, report_data: &[u8; 64]) -> Vec<u8> {
    let mut quote = vec![0u8; 1020];

    // Quote Header
    quote[0..2].copy_from_slice(&3u16.to_le_bytes()); // Version 3
    quote[2..4].copy_from_slice(&2u16.to_le_bytes()); // Sign Type (ECDSA P-256)

    // ISV Enclave Report starts at offset 48
    let report_offset = 48;

    // MRENCLAVE (32 bytes at offset 48 + 64 = 112)
    let mrenclave_bytes = hex::decode(mrenclave_hex).expect("Invalid mrenclave hex");
    quote[report_offset + 64..report_offset + 96].copy_from_slice(&mrenclave_bytes);

    // MRSIGNER (32 bytes at offset 48 + 128 = 176)
    let mrsigner_bytes = hex::decode(mrsigner_hex).expect("Invalid mrsigner hex");
    quote[report_offset + 128..report_offset + 160].copy_from_slice(&mrsigner_bytes);

    // REPORT DATA (64 bytes at offset 48 + 320 = 368)
    quote[report_offset + 320..report_offset + 384].copy_from_slice(report_data);

    quote
}
