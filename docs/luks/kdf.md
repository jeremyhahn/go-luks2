# Key Derivation Functions

LUKS2 uses Key Derivation Functions (KDFs) to convert passphrases into cryptographic keys resistant to brute-force attacks.

## Supported KDFs

| KDF | Type | Resistance | Use Case |
|-----|------|------------|----------|
| Argon2id | Memory-hard | Best | Default, recommended |
| Argon2i | Memory-hard | Good | Side-channel protection |
| PBKDF2 | Iterative | Moderate | FIPS compliance, compatibility |

## Argon2id (Recommended)

Argon2id combines Argon2i (data-independent) and Argon2d (data-dependent) for optimal security.

### Parameters

```json
{
  "type": "argon2id",
  "salt": "base64-encoded-32-byte-salt",
  "time": 4,
  "memory": 1048576,
  "cpus": 4
}
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| time | Iterations (time cost) | 4 |
| memory | Memory in KB | 1048576 (1 GB) |
| cpus | Parallelism (threads) | 4 |

### Security Properties

- **Memory-hard**: Requires significant RAM, resists GPU attacks
- **Time-hard**: Multiple iterations increase computation time
- **Parallel**: Uses multiple CPU cores

### Example Configuration

```go
opts := luks2.FormatOptions{
    KDFType:        "argon2id",
    Argon2Time:     4,        // 4 iterations
    Argon2Memory:   1048576,  // 1 GB
    Argon2Parallel: 4,        // 4 threads
}
```

## Argon2i

Data-independent variant, resistant to side-channel attacks.

### Parameters

Same as Argon2id:

```json
{
  "type": "argon2i",
  "salt": "base64...",
  "time": 4,
  "memory": 1048576,
  "cpus": 4
}
```

### Use Cases

- Systems where timing attacks are a concern
- Shared hosting environments
- When Argon2id is not available

## PBKDF2

Password-Based Key Derivation Function 2, using HMAC.

### Parameters

```json
{
  "type": "pbkdf2",
  "salt": "base64-encoded-salt",
  "hash": "sha256",
  "iterations": 100000
}
```

| Parameter | Description | Typical Value |
|-----------|-------------|---------------|
| hash | Hash algorithm | sha256, sha512 |
| iterations | Number of iterations | 100000-2000000 |

### Supported Hashes

| Hash | Output Size | FIPS Compliant |
|------|-------------|----------------|
| sha1 | 160 bits | Yes |
| sha256 | 256 bits | Yes |
| sha384 | 384 bits | Yes |
| sha512 | 512 bits | Yes |

### Example Configuration

```go
opts := luks2.FormatOptions{
    KDFType:       "pbkdf2",
    HashAlgo:      "sha256",
    PBKDFIterTime: 2000,  // Target 2 seconds
}
```

### FIPS Compliance

PBKDF2 is the only FIPS 140-2 approved KDF:

```go
// Check if KDF is FIPS compliant
if luks2.IsFIPSCompliantKDF("pbkdf2") {
    // Use for FIPS environments
}
```

## Iteration Calibration

LUKS2 calibrates iterations to achieve a target time.

### Automatic Calibration

```go
// Target 2 second unlock time
opts := luks2.FormatOptions{
    KDFType:       "pbkdf2",
    PBKDFIterTime: 2000,  // milliseconds
}
```

### Manual Benchmark

```go
// Benchmark for 2 seconds
iterations := luks2.BenchmarkPBKDF2("sha256", 2000)
fmt.Printf("Recommended iterations: %d\n", iterations)
```

## Salt Generation

Each keyslot uses a unique random salt:

- 32 bytes for Argon2
- 32 bytes for PBKDF2
- Generated using cryptographic random

```go
// Salt is auto-generated during Format
// Never reuse salts across keyslots
```

## Digest KDF

The master key digest always uses PBKDF2:

```json
{
  "digests": {
    "0": {
      "type": "pbkdf2",
      "hash": "sha256",
      "iterations": 100000,
      "salt": "base64...",
      "digest": "base64..."
    }
  }
}
```

This is separate from the keyslot KDF and verifies the decrypted master key.

## Performance Comparison

| KDF | Memory | 1GB Argon2 | Comments |
|-----|--------|-----------|----------|
| Argon2id | High | ~1s | Best security |
| Argon2i | High | ~1s | Side-channel safe |
| PBKDF2 | Low | ~2s | FIPS compatible |

## Security Recommendations

### For New Volumes

Use Argon2id with:
- Memory: 1 GB or more
- Time: 4+ iterations
- CPUs: Match system cores

### For FIPS Compliance

Use PBKDF2 with:
- Hash: SHA-256 or SHA-512
- Iterations: 100,000+ (calibrate for 2+ seconds)

### For Low-Memory Systems

Use PBKDF2 or Argon2 with reduced memory:
- Argon2 memory: 256 MB minimum
- PBKDF2: No memory requirement
