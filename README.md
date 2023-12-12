# plonky2-groth16-verifier
Wraps up plonky2 verifier as a groth16 circuit

# TODOS
- [ ] Apply range check on inputs to the circuit (current implementation leads to non satisfying constraints; commented out for now)
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
