#!/bin/sh
exec docker run --rm -t -v "$(pwd)":/volume clux/muslrust:stable cargo build --release $@
