# plonky2-groth16-verifier
Wraps up plonky2 verifier as a groth16 circuit

# TODOS
- [ ] Implement constraints for rest of the plonky2 gates
    - [ ] ArithmeticExtensionGate
    - [ ] BaseSumGate
    - [ ] CosetInterpolationGate
    - [ ] ExponentiationGate
    - [ ] LookupGate
    - [ ] LookupTableGate
    - [ ] MulExtensionGate
    - [ ] NoopGate
    - [ ] PoseidonMdsGate
    - [ ] RandomAccessGate
    - [ ] ReducingGate
    - [ ] ReducingExtensionGate
- [ ] Implement constraints for lookups in vanishing polynomial evaluation
- [ ] Use poseidon over BN254 scalar field rather than goldilocks field; it will reduce constraints vastly. Also implement the corresponding config for plonky2 prover


# Developer chat
In case you wish to contribute or collaborate, you can join our ZK builder chat at - https://t.me/+leHcoDWYoaFiZDM1
