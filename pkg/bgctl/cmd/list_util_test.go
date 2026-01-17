package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPaginate(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}
	paged, info := paginate(items, 2, 2, false)
	require.Equal(t, []int{3, 4}, paged)
	require.Contains(t, info, "Showing page 2")
}
