#!/bin/bash
go build main.go
go install
plonky2-groth16-verifier build --common_data ./data/goldilocks/common_data.json
