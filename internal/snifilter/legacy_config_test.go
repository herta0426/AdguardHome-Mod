package snifilter

import (
	"testing"

	"github.com/stretchr/testify/require"
	yaml "go.yaml.in/yaml/v4"
)

// TestLegacyFieldsIgnored proves that removing the UIDs and the DropQUIC fields
// from the Params struct does not break loading of an older configuration that
// still contains those keys: it must be unmarshaled without an error, with the
// fields simply ignored.
func TestLegacyFieldsIgnored(t *testing.T) {
	const data = `
queue_num: 7
ports: [443]
uids:
  - 10000-19999
drop_quic: true
`

	var p Params
	err := yaml.Unmarshal([]byte(data), &p)
	require.NoError(t, err)

	require.Equal(t, uint16(7), p.QueueNum)
	require.Equal(t, []uint16{443}, p.Ports)
}
