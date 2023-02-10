# Merkle Tree

This is a simple implementation of a Merkle Tree in Golang.Merkle tree also known as hash tree is a data structure used for data verification and synchronization.
It is a tree data structure where each non-leaf node is a hash of it’s child nodes. All the leaf nodes are at the same depth and are as far left as possible.
It maintains data integrity and uses hash functions for this purpose.

<div align="center">
    <img src="./asset/merkle_tree.svg.png" alt="Merkle Tree Data Structure", style="width: 60%">
</div>

## Functions

New - Build tree from a list of blocks , check test file for more details. It generates
proofs for each block and generates root hash.

Verify - Provide a block and proof to verify if the block is in the tree.

Proof - Generate a proof for a specific block.

Uses SHA256 as the hash function.

## Usage

```
make build - to build the binary
make test - to run the tests
```

## Installation

```
go get -u github.com/hitenjain14/merkle-tree
```

## TODO

- [ ] Add more tests
- [ ] Add more documentation
- [ ] Add parallelism so tree can be built faster
