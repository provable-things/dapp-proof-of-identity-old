# Proof-of-Identity Dapp

This repository is a first attempt to stick different pieces together to get an onchain proof-of-identity which can be reused by any Ethereum smart contract.

This work is based on the IDs issued by the Estonian government as part of their [e-residency program](https://e-estonia.com/e-residents/about/).
By verifying the RSA signatures coming from those devices we link real identities to Ethereum addresses.
We give for granted that something like the [RSA_verify/bigint modpow EIP](https://github.com/ethereum/EIPs/issues/74) is already there.

The two main pieces here are:
* contract.sol (+ [web-ui](https://dapps.oraclize.it/proof-of-identity/)) - the actual contract implementing the linking logic and keeping everything in its storage
* revocationList.sol (+ [web-ui](http://dapps.oraclize.it/esteid-crl/)) - the Oraclize-based contract acting as interface with the Estonian IDs CRL (to verify a given ID certificate is still valid)

This is an elegant solution to solve the "KYC problem" without opening unnecessary trustlines. You can find more informations about the rationale behind this project in [our blog post](http://blog.oraclize.it/2016/04/27/proof-of-identity-on-ethereum/).
