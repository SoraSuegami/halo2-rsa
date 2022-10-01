# halo2-rsa
**RSA verification circuit using halo2 library.**

## Disclaimer
DO NOT USE THIS LIBRARY IN PRODUCTION. At this point, this is under development. It has known and unknown bugs and security flaws.

## Features
This library provides a RSA verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).
It will allow halo2 developers to write circuits for verifying RSA-based cryptographic schemes such as RSA signature, RSA accumulator, and verifiable delay function.
Specifically, our library provides the following two chips.
1. BigIntChip

The BigIntChip defines constraints for big integers, i.e. integers whose size is larger than that of the native field of the arithmetic circuit.
You can perform various operations of the big integers, e.g. allocation, addition, subtraction, multiplication, modular operations, and comparison.

2. RSAChip

The RSAChip defines constraints for verifying the RSA relations.
That is, for the integer `x` and RSA public key `(n, e)`, it computes `x^e mod n`.
Moreover, it also supports the verification of [pkcs1v15 signatures](https://www.rfc-editor.org/rfc/rfc3447).

### Current Development Status
We have completed the development of both chips.
The BigIntChip and RSAChip is placed in the big_integer module and top module, respectively.

## Requirement
- rustc 1.65.0-nightly (0b79f758c 2022-08-18)
- cargo 1.65.0-nightly (9809f8ff3 2022-08-16)

## Installation and Build
You can install and build our library with the following commands.
```bash
git clone https://github.com/SoraSuegami/halo2_rsa.git
cd halo2_rsa
cargo build --release
```

## Usage
You can open the API specification by executing the following command under the halo2_rsa directory.
```bash
cargo doc --open
```

## Test
You can run the tests by executing the following command under the halo2_rsa directory.
```bash
cargo test
```

## Authors
- Sora Suegami

## License
This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/SoraSuegami/halo2_rsa/blob/main/LICENSE.md) file for details

## Acknowledgments
We have developed our library by reference to the [circom-rsa-verify repository](https://github.com/zkp-application/circom-rsa-verify), which contains a circuit of pkcs1v15 signature verification in the circom language. 
It verifies signatures by first defining a circuit for modular multiplication of big integers and then using the circuit to perform modular exponentiation.

We implemented our circuit using a similar approach.
In addition, the range check, the verification of whether a given integer is within a certain range, was optimized using a lookup table.
This optimization allows the prover to prove that multiple integers are in the specified range in batch.