package option

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func TestXHTTPFormatPreservesOmittedOptions(t *testing.T) {
	for _, input := range []string{
		`{"type":"xhttp"}`,
		`{"type":"xhttp","x_padding_bytes":"100-1000"}`,
		`{"type":"xhttp","download":{"server":"example.org","server_port":443}}`,
		`{"type":"xhttp","mode":"packet-up","session_placement":"header","seq_placement":"query","uplink_data_placement":"cookie","xmux":{"max_concurrency":0}}`,
		`{"type":"xhttp","xmux":{"h_keep_alive_period":0}}`,
		`{"type":"xhttp","mode":"auto","x_padding_key":"custom","x_padding_bytes":128,"session_id_length":"8-16","sc_min_posts_interval_ms":0,"xmux":{"max_connections":2}}`,
	} {
		t.Run(input, func(t *testing.T) {
			var options V2RayTransportOptions
			require.NoError(t, json.Unmarshal([]byte(input), &options))
			for range 2 {
				formatted, err := badjson.Omitempty(context.Background(), options)
				require.NoError(t, err)
				encoded, err := json.Marshal(formatted)
				require.NoError(t, err)
				require.JSONEq(t, input, string(encoded))
				options = formatted
			}
		})
	}
}

func TestXHTTPFormatPreservesEmptyXmuxSemantics(t *testing.T) {
	options := V2RayTransportOptions{
		Type: "xhttp",
		XHTTPOptions: V2RayXHTTPOptions{
			V2RayXHTTPBaseOptions: V2RayXHTTPBaseOptions{Xmux: &V2RayXHTTPXmuxOptions{}},
		},
	}
	before, err := options.XHTTPOptions.Normalize()
	require.NoError(t, err)
	formatted, err := badjson.Omitempty(context.Background(), options)
	require.NoError(t, err)
	after, err := formatted.XHTTPOptions.Normalize()
	require.NoError(t, err)
	require.Equal(t, before.Xmux.GetNormalizedMaxConcurrency(), after.Xmux.GetNormalizedMaxConcurrency())
	require.Equal(t, before.Xmux.GetNormalizedHMaxRequestTimes(), after.Xmux.GetNormalizedHMaxRequestTimes())
	require.Equal(t, before.Xmux.GetNormalizedHMaxReusableSecs(), after.Xmux.GetNormalizedHMaxReusableSecs())
}

func TestXHTTPPaddingDefault(t *testing.T) {
	var options V2RayTransportOptions
	require.NoError(t, json.Unmarshal([]byte(`{"type":"xhttp","download":{"server":"example.org"}}`), &options))
	want := badoption.Range[int]{From: 100, To: 1000}
	require.Equal(t, want, options.XHTTPOptions.GetNormalizedXPaddingBytes())
	require.Equal(t, want, options.XHTTPOptions.Download.GetNormalizedXPaddingBytes())
}

func TestXHTTPNormalizePreservesConfiguration(t *testing.T) {
	input := `{"mode":"packet-up","session_placement":"header","seq_placement":"query","uplink_data_placement":"cookie","uplink_http_method":"get","download":{"server":"example.org","server_port":443}}`
	var options V2RayXHTTPOptions
	require.NoError(t, json.Unmarshal([]byte(input), &options))
	normalized, err := options.Normalize()
	require.NoError(t, err)
	require.Equal(t, "GET", normalized.UplinkHTTPMethod)
	require.Equal(t, "X-Session", normalized.SessionKey)
	require.Equal(t, "x_seq", normalized.SeqKey)
	require.Equal(t, "x_data", normalized.UplinkDataKey)
	for _, base := range []*V2RayXHTTPBaseOptions{&normalized.V2RayXHTTPBaseOptions, &normalized.Download.V2RayXHTTPBaseOptions} {
		require.Equal(t, "x_padding", base.XPaddingKey)
		require.Equal(t, "X-Padding", base.XPaddingHeader)
		require.Equal(t, PlacementQueryInHeader, base.XPaddingPlacement)
		require.Equal(t, "repeat-x", base.XPaddingMethod)
		require.Equal(t, badoption.Range[int]{From: 100, To: 1000}, base.GetNormalizedXPaddingBytes())
		require.NotNil(t, base.Xmux)
		require.Equal(t, badoption.Range[int]{From: 1, To: 1}, base.Xmux.GetNormalizedMaxConcurrency())
		require.Equal(t, badoption.Range[int]{From: 600, To: 900}, base.Xmux.GetNormalizedHMaxRequestTimes())
		require.Equal(t, badoption.Range[int]{From: 1800, To: 3000}, base.Xmux.GetNormalizedHMaxReusableSecs())
	}
	require.Equal(t, "POST", normalized.Download.UplinkHTTPMethod)
	require.Equal(t, PlacementAuto, normalized.Download.UplinkDataPlacement)
	require.Equal(t, "X-Data", normalized.Download.UplinkDataKey)
	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, input, string(encoded))

	options = V2RayXHTTPOptions{}
	require.NoError(t, json.Unmarshal([]byte(`{"xmux":{"max_concurrency":0}}`), &options))
	normalized, err = options.Normalize()
	require.NoError(t, err)
	require.Equal(t, "auto", normalized.Mode)
	require.Equal(t, badoption.Range[int]{}, normalized.Xmux.GetNormalizedMaxConcurrency())
	require.Equal(t, badoption.Range[int]{}, normalized.Xmux.GetNormalizedHMaxRequestTimes())
}

func TestXHTTPRejectsInvalidOptions(t *testing.T) {
	for _, fields := range []string{
		`"x_padding_bytes":0`,
		`"x_padding_bytes":"0-100"`,
		`"x_padding_bytes":-1`,
		`"mode":"unknown"`,
		`"x_padding_placement":"unknown"`,
		`"uplink_http_method":"GET"`,
		`"uplink_data_placement":"cookie"`,
		`"server_max_header_bytes":-1`,
		`"sc_max_each_post_bytes":0`,
		`"xmux":{"max_connections":2,"max_concurrency":2}`,
	} {
		t.Run(fields, func(t *testing.T) {
			var options V2RayTransportOptions
			require.Error(t, json.Unmarshal([]byte(`{"type":"xhttp",`+fields+`}`), &options))
			if fields != `"mode":"unknown"` {
				options = V2RayTransportOptions{}
				require.Error(t, json.Unmarshal([]byte(`{"type":"xhttp","download":{`+fields+`}}`), &options))
			}
		})
	}
}
