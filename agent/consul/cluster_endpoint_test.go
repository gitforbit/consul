package consul

import (
	"encoding/base64"
	"io/ioutil"
	"math/rand"
	"net"
	"path"
	"testing"
	"time"

	"github.com/hashicorp/consul/agent/agentpb"
	"github.com/hashicorp/consul/agent/agentpb/config"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/internal/go-sso/oidcauth/oidcauthtest"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/consul/tlsutil"
	"github.com/hashicorp/memberlist"
	msgpackrpc "github.com/hashicorp/net-rpc-msgpackrpc"
	"github.com/stretchr/testify/require"

	"gopkg.in/square/go-jose.v2/jwt"
)

func testJWTStandardClaims() jwt.Claims {
	now := time.Now()

	return jwt.Claims{
		Subject:   "consul",
		Issuer:    "consul",
		Audience:  jwt.Audience{"consul"},
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
		Expiry:    jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
}

func signJWT(t *testing.T, privKey string, claims jwt.Claims, privateClaims interface{}) string {
	t.Helper()
	token, err := oidcauthtest.SignJWT(privKey, claims, privateClaims)
	require.NoError(t, err)
	return token
}

func signJWTWithStandardClaims(t *testing.T, privKey string, claims interface{}) string {
	t.Helper()
	return signJWT(t, privKey, testJWTStandardClaims(), claims)
}

// TestClusterAutoConfig is really an integration test of all the moving parts of the Cluster.AutoConfig RPC.
// Full testing of the individual parts will not be done in this test:
//
//  * Any implementations of the AutoConfigAuthorizer interface (although these test do use the jwtAuthorizer)
//  * Each of the individual config generation functions. These can be unit tested separately and many wont
//    require a running test server.
func TestClusterAutoConfig(t *testing.T) {
	type testCase struct {
		request       agentpb.AutoConfigRequest
		expected      agentpb.AutoConfigResponse
		patchResponse func(t *testing.T, srv *Server, resp *agentpb.AutoConfigResponse)
		err           string
	}

	gossipKey := make([]byte, 32)
	// this is not cryptographic randomness and is not secure but for the sake of this test its all we need.
	n, err := rand.Read(gossipKey)
	require.NoError(t, err)
	require.Equal(t, 32, n)

	gossipKeyEncoded := base64.StdEncoding.EncodeToString(gossipKey)

	// generate a test certificate for the server serving out the insecure RPC
	cert, key, cacert, err := testTLSCertificates("server.dc1.consul")
	require.NoError(t, err)

	// generate a JWT signer
	pub, priv, err := oidcauthtest.GenerateKey()
	require.NoError(t, err)

	_, altpriv, err := oidcauthtest.GenerateKey()
	require.NoError(t, err)

	cases := map[string]testCase{
		"wrong-datacenter": {
			request: agentpb.AutoConfigRequest{
				Datacenter: "no-such-dc",
			},
			err: `invalid datacenter "no-such-dc" - agent auto configuration cannot target a remote datacenter`,
		},
		"unverifiable": {
			request: agentpb.AutoConfigRequest{
				Node: "test-node",
				// this is signed using an incorrect private key
				JWT: signJWTWithStandardClaims(t, altpriv, map[string]interface{}{"consul_node_name": "test-node"}),
			},
			err: "Permission denied: Failed JWT authorization: no known key successfully validated the token signature",
		},
		"claim-assertion-failed": {
			request: agentpb.AutoConfigRequest{
				Node: "test-node",
				JWT:  signJWTWithStandardClaims(t, priv, map[string]interface{}{"wrong_claim": "test-node"}),
			},
			err: "Permission denied: Failed JWT claim assertion",
		},
		"good": {
			request: agentpb.AutoConfigRequest{
				Node: "test-node",
				JWT:  signJWTWithStandardClaims(t, priv, map[string]interface{}{"consul_node_name": "test-node"}),
			},
			expected: agentpb.AutoConfigResponse{
				Config: &config.Config{
					Datacenter:        "dc1",
					PrimaryDatacenter: "dc1",
					NodeName:          "test-node",
					AutoEncrypt: &config.AutoEncrypt{
						TLS: true,
					},
					ACL: &config.ACL{
						Enabled:       true,
						PolicyTTL:     "30s",
						TokenTTL:      "30s",
						RoleTTL:       "30s",
						DisabledTTL:   "0s",
						DownPolicy:    "extend-cache",
						DefaultPolicy: "deny",
						Tokens: &config.ACLTokens{
							Agent: "patched-secret",
						},
					},
					EncryptKey:                  gossipKeyEncoded,
					EncryptVerifyIncoming:       true,
					EncryptVerifyOutgoing:       true,
					VerifyOutgoing:              true,
					VerifyServerHostname:        true,
					TLSMinVersion:               "tls12",
					TLSPreferServerCipherSuites: true,
				},
			},
			patchResponse: func(t *testing.T, srv *Server, resp *agentpb.AutoConfigResponse) {
				// we are expecting an ACL token but cannot check anything for equality
				// so here we check that it was set and overwrite it
				require.NotNil(t, resp.Config)
				require.NotNil(t, resp.Config.ACL)
				require.NotNil(t, resp.Config.ACL.Tokens)
				require.NotEmpty(t, resp.Config.ACL.Tokens.Agent)
				resp.Config.ACL.Tokens.Agent = "patched-secret"

				// we don't know the expected join address until we start up the test server
				joinAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: srv.config.SerfLANConfig.MemberlistConfig.AdvertisePort}
				require.Equal(t, []string{joinAddr.String()}, resp.Config.RetryJoinLAN)
				resp.Config.RetryJoinLAN = nil
			},
		},
	}

	_, s, _ := testACLServerWithConfig(t, func(c *Config) {
		c.Domain = "consul"
		c.AutoConfigAuthzEnabled = true
		c.AutoConfigAuthzAuthMethod = structs.ACLAuthMethod{
			Name:           "Auth Config Authorizer",
			Type:           "jwt",
			EnterpriseMeta: *structs.DefaultEnterpriseMeta(),
			Config: map[string]interface{}{
				"BoundAudiences":       []string{"consul"},
				"BoundIssuer":          "consul",
				"JWTValidationPubKeys": []string{pub},
				"ClaimMappings": map[string]string{
					"consul_node_name": "node",
				},
			},
		}
		c.AutoConfigAuthzClaimAssertions = []string{
			`value.node == "${node}"`,
		}
		c.AutoConfigAuthzAllowReuse = true

		cafile := path.Join(c.DataDir, "cacert.pem")
		err := ioutil.WriteFile(cafile, []byte(cacert), 0600)
		require.NoError(t, err)

		certfile := path.Join(c.DataDir, "cert.pem")
		err = ioutil.WriteFile(certfile, []byte(cert), 0600)
		require.NoError(t, err)

		keyfile := path.Join(c.DataDir, "key.pem")
		err = ioutil.WriteFile(keyfile, []byte(key), 0600)
		require.NoError(t, err)

		c.CAFile = cafile
		c.CertFile = certfile
		c.KeyFile = keyfile
		c.VerifyOutgoing = true
		c.VerifyIncoming = true
		c.VerifyServerHostname = true
		c.TLSMinVersion = "tls12"
		c.TLSPreferServerCipherSuites = true

		c.ConnectEnabled = true
		c.AutoEncryptAllowTLS = true
		c.SerfLANConfig.MemberlistConfig.GossipVerifyIncoming = true
		c.SerfLANConfig.MemberlistConfig.GossipVerifyOutgoing = true

		keyring, err := memberlist.NewKeyring(nil, gossipKey)
		require.NoError(t, err)
		c.SerfLANConfig.MemberlistConfig.Keyring = keyring
	}, false)

	conf := tlsutil.Config{
		CAFile:               s.config.CAFile,
		VerifyServerHostname: s.config.VerifyServerHostname,
		VerifyOutgoing:       s.config.VerifyOutgoing,
		Domain:               s.config.Domain,
	}
	codec, err := insecureRPCClient(s, conf)
	require.NoError(t, err)

	waitForLeaderEstablishment(t, s)

	for testName, tcase := range cases {
		t.Run(testName, func(t *testing.T) {
			var reply agentpb.AutoConfigResponse
			err := msgpackrpc.CallWithCodec(codec, "Cluster.AutoConfig", &tcase.request, &reply)
			if tcase.err != "" {
				testutil.RequireErrorContains(t, err, tcase.err)
			} else {
				require.NoError(t, err)
				if tcase.patchResponse != nil {
					tcase.patchResponse(t, s, &reply)
				}
				require.Equal(t, tcase.expected, reply)
			}
		})
	}
}
