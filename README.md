# HMAC-DRBG Pseudorandom Number Generator

Implementation of a **HMAC-based Deterministic Random Bit Generator (HMAC-DRBG)** according to the NIST SP 800-90A standard. This project was developed as part of a cryptography course module covering pseudorandom number generators based on authentication codes (HMAC).

##  Project Context

**Module:** Cryptography & Security  
**Subject:** Sujet 3 - Générateur de nombre pseudo aléatoire à base des codes d'authentification HMAC  
**Standard:** NIST SP 800-90A - Recommendation for Random Number Generation Using Deterministic Random Bit Generators

---

##  Features

-  **NIST SP 800-90A compliant** HMAC-DRBG implementation
-  **SHA-256** based cryptographic security (256-bit security strength)
-  **Deterministic output** with seed control for reproducibility
-  **Automatic reseeding** with system entropy (`os.urandom`)
-  **Pythonic API** similar to standard `random` module
-  **Comprehensive unit tests** with statistical validation
-  **Zero external dependencies** - uses only Python standard library

---

## Algorithm Overview

HMAC-DRBG uses the HMAC (Hash-based Message Authentication Code) construction to generate pseudorandom bits. The algorithm maintains two internal state values:

- **K**: Key for HMAC operations (256 bits)
- **V**: Value for generating output (256 bits)

### Core Operations

| Operation | Description |
|-----------|-------------|
| `Instantiate` | Initialize K and V with seed material |
| `Update` | Update internal state using HMAC |
| `Generate` | Produce pseudorandom output blocks |
| `Reseed` | Inject fresh entropy into the state |

---

## Installation & Usage

### Clone the repository
```bash
git clone https://github.com/kamisara/hmac-prng-project.git
cd hmac-prng-project