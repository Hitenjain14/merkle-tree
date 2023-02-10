package merkletree

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerkleTree(t *testing.T) {

	sl := make([]Block, 0)

	for i := 0; i < 4; i++ {
		b := Block{Data: []byte(strconv.FormatInt(int64(i), 10))}
		sl = append(sl, b)
	}

	m, err := New(sl)
	assert.Nil(t, err)

	assert.Equal(t, int(4), m.NumLeaves)

	assert.Equal(t, uint32(2), m.Depth)

	bx := Block{Data: []byte(strconv.FormatInt(int64(2), 10))}
	bxx := Block{Data: []byte(strconv.FormatInt(int64(3), 10))}

	flag, err := m.Verify(bx, m.Proofs[2])
	assert.Nil(t, err)
	assert.True(t, flag)

	pr, err := m.Proof(bxx)
	assert.Nil(t, err)
	flag, err = m.Verify(bxx, pr)
	assert.Nil(t, err)
	assert.True(t, flag)

}
