package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/config"
	targetspb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/servers/worker"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

func TestWorkerSessionCleanup(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(t, err)

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
	})
	defer c1.Shutdown()

	expectWorkers(t, c1)

	ctx := c1.Context()

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:      c1.Config().WorkerAuthKms,
		InitialControllers: c1.ClusterAddrs(),
		Logger:             logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w1)

	// Set up target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Create test server, update default port on target
	ts := newTestTcpServer(t)
	require.NotNil(t, ts)
	defer ts.Close()
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()))
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Authorize
	sar, err := tcl.AuthorizeSession(ctx, "ttcp_1234567890")
	require.NoError(t, err)
	require.NotNil(t, sar)

	tsad := newTestSessionAuthData(t, sar)
	require.NotNil(t, tsad)

	// Connect to worker proxy
	conn := tsad.Connect(ctx)
	require.NotNil(t, conn)
	defer conn.Close()

	// Run send/receive test
	sendRecvResultCh := make(chan int)
	go testSendRecv(t, conn, 60, sendRecvResultCh)
	actualSendRecv := <-sendRecvResultCh
	require.Less(t, actualSendRecv, 31)
}

// testSendRecv runs a basic send/receive test over the returned
// connection and returns the amount of "pings" successfully sent.
//
// The test is a simple sequence number, ticking up every second to
// max. The passed in conn is expected to copy whatever it is
// received.
//
// resultCh, if not nil, is also sent the result on completion. This
// allows for execution to be called concurrently to do other things
// like close the connection, etc. The channel is closed after the
// result is sent.
func testSendRecv(t *testing.T, conn net.Conn, max uint32, resultCh chan int) int {
	t.Helper()

	var i uint32
	for ; i < max; i++ {
		// Shuttle over the sequence number as base64.
		err := binary.Write(conn, binary.LittleEndian, i)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}

			require.FailNow(t, err.Error())
		}

		// Read it back
		var j uint32
		err = binary.Read(conn, binary.LittleEndian, &j)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}

			require.FailNow(t, err.Error())
		}

		require.Equal(t, j, i)

		// Sleep 1s
		time.Sleep(time.Second)
	}

	if resultCh != nil {
		resultCh <- int(i)
		close(resultCh)
	}

	return int(i)
}

type testSessionAuthData struct {
	t          *testing.T
	workerAddr string
	transport  *http.Transport
}

// newTestSessionAuthData derives a bunch of authorization data that
// we need from a session's authorization token. This is a relatively
// complex process that does not have much to do with describing the
// test, and may need to be repeated, so we abstract it here.
func newTestSessionAuthData(t *testing.T, sar *targets.SessionAuthorizationResult) *testSessionAuthData {
	t.Helper()
	result := &testSessionAuthData{
		t: t,
	}

	authzString := sar.GetItem().(*targets.SessionAuthorization).AuthorizationToken
	marshaled, err := base58.FastBase58Decoding(authzString)
	require.NoError(t, err)
	require.NotZero(t, marshaled)

	sessionAuthzData := new(targetspb.SessionAuthorizationData)
	err = proto.Unmarshal(marshaled, sessionAuthzData)
	require.NoError(t, err)
	require.NotZero(t, sessionAuthzData.GetWorkerInfo())

	result.workerAddr = sessionAuthzData.GetWorkerInfo()[0].GetAddress()

	parsedCert, err := x509.ParseCertificate(sessionAuthzData.Certificate)
	require.NoError(t, err)
	require.Len(t, parsedCert.DNSNames, 1)

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{sessionAuthzData.Certificate},
				PrivateKey:  ed25519.PrivateKey(sessionAuthzData.PrivateKey),
				Leaf:        parsedCert,
			},
		},
		RootCAs:    certPool,
		ServerName: parsedCert.DNSNames[0],
		MinVersion: tls.VersionTLS13,
	}

	result.transport = cleanhttp.DefaultTransport()
	result.transport.DisableKeepAlives = false
	result.transport.TLSClientConfig = tlsConf
	result.transport.IdleConnTimeout = 0

	return result
}

// Connect returns a connected websocket for the stored session auth
// data, connecting to the stored workerAddr with the configured
// transport.
//
// The returned (wrapped) net.Conn should be ready for communication.
func (d *testSessionAuthData) Connect(ctx context.Context) net.Conn {
	d.t.Helper()

	conn, resp, err := websocket.Dial(
		ctx,
		fmt.Sprintf("wss://%s/v1/proxy", d.workerAddr),
		&websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: d.transport,
			},
			Subprotocols: []string{globals.TcpProxyV1},
		},
	)
	require.NoError(d.t, err)
	require.NotNil(d.t, conn)
	require.NotNil(d.t, resp)
	require.Equal(d.t, resp.Header.Get("Sec-WebSocket-Protocol"), globals.TcpProxyV1)

	// Send the handshake.
	tofuToken, err := base62.Random(20)
	require.NoError(d.t, err)
	handshake := proxy.ClientHandshake{TofuToken: tofuToken}
	err = wspb.Write(ctx, conn, &handshake)
	require.NoError(d.t, err)

	// Receive/check the handshake
	var handshakeResult proxy.HandshakeResult
	err = wspb.Read(ctx, conn, &handshakeResult)
	require.NoError(d.t, err)
	// This is just a cursory check to make sure that the handshake is
	// populated. We could check connections remaining too, but that
	// could legitimately be a trivial (zero) value.
	require.NotNil(d.t, handshakeResult.GetExpiration())

	return websocket.NetConn(ctx, conn, websocket.MessageBinary)
}

type testTcpServer struct {
	t     *testing.T // For logging
	ln    net.Listener
	conns map[string]net.Conn
}

func (ts *testTcpServer) Port() uint32 {
	_, portS, err := net.SplitHostPort(ts.ln.Addr().String())
	if err != nil {
		panic(err)
	}

	if portS == "" {
		panic("empty port in what should be TCP listener")
	}

	port, err := strconv.Atoi(portS)
	if err != nil {
		panic(err)
	}

	if port < 1 {
		panic("zero or negative port in what should be a TCP listener")
	}

	return uint32(port)
}

func (ts *testTcpServer) Close() {
	ts.ln.Close()
	for _, conn := range ts.conns {
		conn.Close()
	}
}

func (ts *testTcpServer) run() {
	for {
		conn, err := ts.ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				ts.t.Logf("Accept() error in testTcpServer: %s", err)
			}

			return
		}

		ts.conns[conn.RemoteAddr().String()] = conn

		go func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
		}(conn)
	}
}

func newTestTcpServer(t *testing.T) *testTcpServer {
	t.Helper()

	ts := &testTcpServer{
		t:     t,
		conns: make(map[string]net.Conn),
	}
	var err error
	ts.ln, err = net.Listen("tcp", ":0")
	require.NoError(t, err)

	go ts.run()
	return ts
}
