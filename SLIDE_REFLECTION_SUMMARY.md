# Slide and Reflection Audit Summary

The complete pair lists and 16-round orientation tables are preserved in 
`slide_and_reflection_audit_full.json`. This report presents counts and 
summary statistics only.

| Variant | Period | Unique rows | Structural repeat pairs | Keyed repeat pairs | Palindrome | Inverse positions | Transpose positions |
|---|---:|---:|---:|---:|---|---:|---:|
| static | 1 | 1 | 120 | 0 | true | 0 | 0 |
| rotor | 4 | 4 | 24 | 0 | false | 0 | 0 |
| round_only | 4 | 4 | 24 | 0 | false | 0 | 0 |
| position_only | 1 | 1 | 120 | 0 | true | 0 | 0 |
| optimized | 8 | 7 | 12 | 0 | false | 0 | 0 |

## Key findings

- **static:** period 1; 120 structural repeat pairs; 0 full keyed repeat pairs; adjacent-key Hamming distance min/mean/max 58/65.133/74; reflected-key XOR Hamming distance min/mean/max 53/61.5/71.
- **rotor:** period 4; 24 structural repeat pairs; 0 full keyed repeat pairs; adjacent-key Hamming distance min/mean/max 58/65.133/74; reflected-key XOR Hamming distance min/mean/max 53/61.5/71.
- **round_only:** period 4; 24 structural repeat pairs; 0 full keyed repeat pairs; adjacent-key Hamming distance min/mean/max 58/65.133/74; reflected-key XOR Hamming distance min/mean/max 53/61.5/71.
- **position_only:** period 1; 120 structural repeat pairs; 0 full keyed repeat pairs; adjacent-key Hamming distance min/mean/max 58/65.133/74; reflected-key XOR Hamming distance min/mean/max 53/61.5/71.
- **optimized:** period 8; 12 structural repeat pairs; 0 full keyed repeat pairs; adjacent-key Hamming distance min/mean/max 58/65.133/74; reflected-key XOR Hamming distance min/mean/max 53/61.5/71.

## Interpretation boundary

No exact keyed-round repetition or exact encryption/decryption reflection is 
demonstrated when the corresponding counts are zero. Structural periodicity or 
palindromic schedule rows are diagnostic flags only and are not attacks.
