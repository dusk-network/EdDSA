
# EdDSA
Implementation of the EdDSA for JubJub curve 
group using Poseidon as the hash function. 
Implementation designed by the [dusk](https://dusk.network) 
team.

## About 
The EdDSA is a digital signature algorithm,
which uses Twisted Edwards curves for creating 
signatures. The original paper was written by 
Bernstein et Al and can be found [here] (https://ed25519.cr.yp.to/ed25519-20110926.pdf). 

The implementation has been created using the
Poseidon hash function, the paper for which can 
be found [here](https://eprint.iacr.org/2019/458.pdf). 

For a reference to the algorithm, please see the [docs]
(https://app.gitbook.com/@dusk-network/s/specs/specifications/phoenix/eddsa).

**This structure of this library is as follows:** 

- Key Generation 
- Signature Generation 
- Signature Verification 

## Licensing
This code is licensed under Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for further info.
