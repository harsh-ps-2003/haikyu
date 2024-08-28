#!/bin/bash
if ! command -v go &> /dev/null
then
    echo "Please install Go first"
    exit 1
else
    go mod tidy
    go run cmd/main.go > info.log
fi