# Manual Testing Checklist

## Security Verification Tasks

- **Encryption Verification**: Confirm all payloads are encrypted (no plaintext visible)
- **Certificate Validation**: Test BAD_CERT rejection on invalid/self-signed/expired certificates
- **Tampering Detection**: Verify SIG_FAIL on modified ciphertext (bit flipping test)
- **Replay Protection**: Confirm REPLAY rejection when reusing sequence numbers
- **Non-Repudiation**: Validate transcript generation and signed SessionReceipt
