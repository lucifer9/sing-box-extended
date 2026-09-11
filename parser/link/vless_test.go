package link

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/stretchr/testify/require"
)

func TestVLESSXHTTPExtraOptionsRoundTrip(t *testing.T) {
	for _, test := range []struct {
		extra string
		want  string
	}{
		{
			extra: `{"xPaddingBytes":"100-200","xmux":{"maxConcurrency":"0","maxConnections":"2","cMaxReuseTimes":"3-4","hMaxRequestTimes":"5-6","hMaxReusableSecs":"7-8","hKeepAlivePeriod":"0"}}`,
			want:  `{"type":"xhttp","x_padding_bytes":"100-200","xmux":{"max_concurrency":0,"max_connections":2,"c_max_reuse_times":"3-4","h_max_request_times":"5-6","h_max_reusable_secs":"7-8","h_keep_alive_period":0}}`,
		},
		{
			extra: `{"xmux":{}}`,
			want:  `{"type":"xhttp","xmux":{"max_concurrency":0}}`,
		},
	} {
		t.Run(test.extra, func(t *testing.T) {
			link := "vless://11111111-1111-4111-8111-111111111111@example.org:443?type=xhttp&extra=" + base64.RawURLEncoding.EncodeToString([]byte(test.extra))
			outbound, err := parseVLESSLink(link)
			require.NoError(t, err)
			transport := outbound.Options.(*option.VLESSOutboundOptions).Transport
			formatted, err := badjson.Omitempty(context.Background(), transport)
			require.NoError(t, err)
			encoded, err := json.Marshal(formatted)
			require.NoError(t, err)
			require.JSONEq(t, test.want, string(encoded))
		})
	}
}
