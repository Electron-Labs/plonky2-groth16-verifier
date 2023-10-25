#!/bin/bash
go build main.go
go install
plonky2-groth16-verifier build --config ./plonky2_config.json --common_data ./data/goldilocks/common_data.json
