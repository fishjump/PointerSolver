#!/usr/bin/env bash

GHIDRA_HEADLESS="/opt/ghidra/support/analyzeHeadless"

BASE=$(dirname "$0")
PROJECT=$(realpath --relative-to="$(pwd)" "$BASE/..")

function compile {
    gcc -O0 $BASE/$1.c -o $BASE/$1
}

function clean {
    rm -rf $BASE/$1
}

function ghidra {
    mkdir -p $PROJECT/ghidra 
    OUT_DIR=$BASE $GHIDRA_HEADLESS $PROJECT/ghidra ghidra -overwrite -import $BASE/$1 -scriptPath $PROJECT/ghidra_script -postscript GhidraMetaDumpHeadless.java
}

function solver {
    # check main function only
    cabal run pointer-solver -- $BASE/$1.json main
}

function runCase {
    echo "Running $1..."
    compile $1
    ghidra $1
    solver $1
    clean $1
}


function main {
    runCase case1
    runCase case2
}

main $@
