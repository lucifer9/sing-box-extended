package option

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestRouteActionUseSniffedDestination(t *testing.T) {
	for _, input := range []string{
		`{"action":"route","outbound":"proxy","use_sniffed_destination":true}`,
		`{"outbound":"proxy","use_sniffed_destination":true}`,
	} {
		var action RuleAction
		require.NoError(t, json.Unmarshal([]byte(input), &action))
		encoded, err := json.Marshal(action)
		require.NoError(t, err)
		require.JSONEq(t, `{"outbound":"proxy","use_sniffed_destination":true}`, string(encoded))
	}
}

func TestRouteActionUseSniffedDestinationConflict(t *testing.T) {
	var action RuleAction
	err := json.Unmarshal([]byte(`{"action":"route","outbound":"proxy","use_sniffed_destination":true,"override_address":"example.org"}`), &action)
	require.ErrorContains(t, err, "`use_sniffed_destination` and `override_address` are mutually exclusive")
}

func TestUseSniffedDestinationOnlyOnRoute(t *testing.T) {
	for _, actionType := range []string{"route-options", "sniff", "bypass", "direct", "reject", "resolve"} {
		t.Run(actionType, func(t *testing.T) {
			var action RuleAction
			err := json.Unmarshal([]byte(`{"action":"`+actionType+`","use_sniffed_destination":true}`), &action)
			require.Error(t, err)
		})
	}
	for _, input := range []string{
		`{"action":"route","outbound":"proxy"}`,
		`{"action":"route","outbound":"proxy","use_sniffed_destination":false,"override_address":"example.org"}`,
		`{"action":"route","outbound":"proxy","use_sniffed_destination":true,"override_port":8443}`,
	} {
		var action RuleAction
		require.NoError(t, json.Unmarshal([]byte(input), &action))
	}
	var action RuleAction
	require.ErrorContains(t, json.Unmarshal([]byte(`{"outbound":"proxy","unknown":true}`), &action), "unknown field")
}

func TestDNSRuleActionRespondUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var action DNSRuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"respond"}`), &action)
	require.NoError(t, err)
	require.Equal(t, C.RuleActionTypeRespond, action.Action)
	require.Equal(t, DNSRouteActionOptions{}, action.RouteOptions)
}

func TestDNSRuleActionRespondRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	var action DNSRuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"respond","disable_cache":true}`), &action)
	require.ErrorContains(t, err, "unknown field")
}
