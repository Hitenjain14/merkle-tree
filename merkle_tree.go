package merkletree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

type MerkleTree struct {
	leafMap   map[string]int
	nodes     [][][]byte
	Root      []byte
	Leaves    [][]byte
	Proofs    []*Proof
	Depth     uint32
	NumLeaves int
}

type Proof struct {
	Siblings [][]byte
	Path     uint32
}

type DataBlock interface {
	Serialize() ([]byte, error)
}

type Block struct {
	Data []byte
}

func (b *Block) Serialize() ([]byte, error) {
	return b.Data, nil
}

func New(blocks []Block) (m *MerkleTree, err error) {

	if len(blocks) <= 1 {
		return nil, errors.New("blocks must be greater than 1")
	}

	m = &MerkleTree{
		leafMap:   make(map[string]int),
		NumLeaves: len(blocks),
		Depth:     callTreeDepth(len(blocks)),
	}

	m.Leaves, err = m.leafGen(blocks)
	if err != nil {
		return nil, err
	}

	//build tree
	if err = m.treeBuild(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *MerkleTree) Verify(dataBlock Block, proof *Proof) (bool, error) {

	return verify(dataBlock, proof, m.Root)

}

func (m *MerkleTree) Proof(dataBlock Block) (*Proof, error) {

	leaf, err := leafFromBlock(dataBlock)
	if err != nil {
		return nil, err
	}

	idx, ok := m.leafMap[string(leaf)]
	if !ok {
		return nil, errors.New("block not found in merkle tree")
	}

	siblings := make([][]byte, m.Depth)
	var path uint32

	for i := uint32(0); i < m.Depth; i++ {
		if idx&1 == 1 {
			siblings[i] = m.nodes[i][idx-1]
		} else {
			siblings[i] = m.nodes[i][idx+1]
			path += 1 << i
		}
		idx >>= 1
	}
	return &Proof{Siblings: siblings, Path: path}, nil
}

func (m *MerkleTree) treeBuild() (err error) {

	for i := 0; i < m.NumLeaves; i++ {
		m.leafMap[string(m.Leaves[i])] = i
	}

	m.nodes = make([][][]byte, m.Depth)
	m.nodes[0] = make([][]byte, m.NumLeaves)

	copy(m.nodes[0], m.Leaves)

	var prevLen int

	if m.nodes[0], prevLen, err = m.fixOdd(m.nodes[0], m.NumLeaves); err != nil {
		return
	}

	for i := uint32(0); i < m.Depth-1; i++ {

		fmt.Println(prevLen >> 1)

		m.nodes[i+1] = make([][]byte, prevLen>>1)

		for j := 0; j < prevLen; j += 2 {
			if m.nodes[i+1][j>>1], err = hashFunc(concatSortHash(m.nodes[i][j], m.nodes[i][j+1])); err != nil {
				return
			}
		}

		if m.nodes[i+1], prevLen, err = m.fixOdd(m.nodes[i+1], len(m.nodes[i+1])); err != nil {
			return
		}
	}
	m.Root, err = hashFunc(concatSortHash(m.nodes[m.Depth-1][0], m.nodes[m.Depth-1][1]))
	if err != nil {
		return
	}
	m.initProofs()
	m.proofGen()
	return
}

func (m *MerkleTree) initProofs() {

	m.Proofs = make([]*Proof, m.NumLeaves)

	for i := 0; i < m.NumLeaves; i++ {
		m.Proofs[i] = new(Proof)
		m.Proofs[i].Siblings = make([][]byte, 0, m.Depth)
	}

}

func (m *MerkleTree) proofGen() {

	for i := 0; i < len(m.nodes); i++ {

		m.updateProofs(m.nodes[i], len(m.nodes[i]), i)

	}

}

func (m *MerkleTree) updateProofs(buf [][]byte, bufLen, step int) {

	batch := 1 << step

	for i := 0; i < bufLen; i += 2 {
		m.updatePairProofs(buf, i, batch, step)
	}

}

func (m *MerkleTree) updatePairProofs(buf [][]byte, idx, batch, step int) {

	start := idx * batch

	end := min(start+batch, m.NumLeaves)

	for i := start; i < end; i++ {
		m.Proofs[i].Siblings = append(m.Proofs[i].Siblings, buf[idx+1])
		m.Proofs[i].Path += 1 << step
	}

	start += batch

	end = min(start+batch, m.NumLeaves)

	for i := start; i < end; i++ {
		m.Proofs[i].Siblings = append(m.Proofs[i].Siblings, buf[idx])
	}

}

func verify(dataBlock Block, proof *Proof, root []byte) (bool, error) {

	if proof == nil {
		return false, errors.New("proof is nil")
	}

	leaf, err := leafFromBlock(dataBlock)

	if err != nil {
		return false, err
	}

	res := make([]byte, len(leaf))
	copy(res, leaf)

	for i := 0; i < len(proof.Siblings); i++ {
		res, err = hashFunc(concatSortHash(res, proof.Siblings[i]))
		if err != nil {
			return false, err
		}
	}
	return bytes.Equal(res, root), nil
}

func (m *MerkleTree) fixOdd(buf [][]byte, prevLen int) ([][]byte, int, error) {

	if prevLen&1 == 0 {
		return buf, prevLen, nil
	}

	var appendNode []byte

	appendNode = buf[prevLen-1]
	prevLen++

	if len(buf) < prevLen {
		buf = append(buf, appendNode)
	} else {
		buf[prevLen-1] = appendNode
	}

	return buf, prevLen, nil
}

func callTreeDepth(blockLen int) uint32 {
	d := uint32(0)

	for blockLen > 1 {
		blockLen = (blockLen + 1) / 2
		d++
	}
	return d
}

func hashFunc(data []byte) ([]byte, error) {
	hasher := sha256.New()
	defer hasher.Reset()
	hasher.Write(data)
	return hasher.Sum(nil), nil
}

func concatSortHash(b1, b2 []byte) []byte {
	if bytes.Compare(b1, b2) < 0 {
		return append(b1, b2...)
	}
	return append(b2, b1...)
}

func (m *MerkleTree) leafGen(blocks []Block) ([][]byte, error) {

	leaves := make([][]byte, m.NumLeaves)
	var err error

	for i := 0; i < m.NumLeaves; i++ {
		if leaves[i], err = leafFromBlock(blocks[i]); err != nil {
			return nil, err
		}
	}

	return leaves, nil

}

func leafFromBlock(block Block) ([]byte, error) {

	blockBytes, err := block.Serialize()
	if err != nil {
		return nil, err
	}

	return hashFunc(blockBytes)

}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
