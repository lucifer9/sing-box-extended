package xhttp_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	xhttp "github.com/sagernet/sing-box/transport/v2rayxhttp"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestXHTTPDefaultOptionsRoundTrip(t *testing.T) {
	for _, config := range []string{
		`{}`,
		`{"x_padding_obfs_mode":true}`,
		`{"xmux":{"max_connections":1,"h_keep_alive_period":0}}`,
		`{"mode":"packet-up","session_placement":"header","seq_placement":"query","uplink_data_placement":"cookie","x_padding_obfs_mode":true}`,
	} {
		t.Run(config, func(t *testing.T) {
			for _, splitDownload := range []bool{false, true} {
				t.Run(fmt.Sprint("download=", splitDownload), func(t *testing.T) {
					var options option.V2RayXHTTPOptions
					require.NoError(t, json.Unmarshal([]byte(config), &options))
					logger := log.NewNOPFactory().Logger()
					server, err := xhttp.NewServer(t.Context(), logger, options, nil, echoHandler{})
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, server.Close()) })
					httpServer := httptest.NewServer(server)
					t.Cleanup(httpServer.Close)
					address := M.SocksaddrFromNet(httpServer.Listener.Addr())
					if splitDownload {
						options.Download = &option.V2RayXHTTPDownloadOptions{
							V2RayXHTTPBaseOptions: options.V2RayXHTTPBaseOptions,
							ServerOptions: option.ServerOptions{
								Server: address.Addr.String(), ServerPort: address.Port,
							},
						}
					}
					before, err := json.Marshal(options)
					require.NoError(t, err)
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					t.Cleanup(cancel)
					client, err := xhttp.NewClient(ctx, logger, N.SystemDialer, address, options, nil)
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, client.Close()) })
					conn, err := client.DialContext(ctx)
					require.NoError(t, err)
					t.Cleanup(func() { conn.Close() })
					payload := []byte("xhttp defaults round trip")
					result := make(chan error, 1)
					go func() {
						if _, err := conn.Write(payload); err != nil {
							result <- err
							return
						}
						reply := make([]byte, len(payload))
						_, err := io.ReadFull(conn, reply)
						if err == nil && string(reply) != string(payload) {
							err = fmt.Errorf("unexpected reply: %q", reply)
						}
						result <- err
					}()
					select {
					case err := <-result:
						require.NoError(t, err)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					after, err := json.Marshal(options)
					require.NoError(t, err)
					require.JSONEq(t, string(before), string(after))
				})
			}
		})
	}
}

type echoHandler struct{}

func (echoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(conn, conn)
		conn.Close()
		onClose(err)
	}()
}
