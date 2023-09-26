/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package sidetree_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	gojose "github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"

	"github.com/trustbloc/did-go/doc/did"
	model "github.com/trustbloc/did-go/doc/did/endpoint"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/doc"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/option/create"
)

type didResolution struct {
	Context          interface{}     `json:"@context"`
	DIDDocument      json.RawMessage `json:"didDocument"`
	ResolverMetadata json.RawMessage `json:"resolverMetadata"`
	MethodMetadata   json.RawMessage `json:"methodMetadata"`
}

func TestClient_CreateDID(t *testing.T) {
	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecUpdatePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithPublicKey(&doc.PublicKey{
				ID:       "key1",
				Type:     doc.JWSVerificationKey2020,
				JWK:      jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: ed25519RecoveryPubKey}},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}))

		require.Contains(t, err.Error(), "sidetree get endpoints func is required")
		require.Nil(t, didResol)

		didResol, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithPublicKey(&doc.PublicKey{
				ID:       "key1",
				Type:     doc.JWSVerificationKey2020,
				JWK:      jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: ed25519RecoveryPubKey}},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}),
			create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return nil, fmt.Errorf("failed to get endpoints")
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoints")
		require.Nil(t, didResol)
	})

	t.Run("test error from send create sidetree request", func(t *testing.T) {
		v := sidetree.New()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ed25519UpdatePubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send request")
		require.Nil(t, didResol)

		// test http status not equal 200
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		didResol, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return []string{serv.URL}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response")
		require.Nil(t, didResol)

		// test failed to parse did
		serv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err1 := (&did.Doc{ID: "did1"}).JSONBytes()
			require.NoError(t, err1)
			_, err1 = fmt.Fprint(w, string(bytes))
			require.NoError(t, err1)
		}))
		defer serv.Close()

		didResol, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return []string{serv.URL}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse did document")
		require.Nil(t, didResol)
	})

	t.Run("test error from sidetree operation request function", func(t *testing.T) {
		v := sidetree.New(sidetree.WithSidetreeOperationRequestFnc(
			func(req []byte, getEndpoints func(bool) ([]string, error)) ([]byte, error) {
				return nil, fmt.Errorf("send operation request error")
			}))

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ed25519UpdatePubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return []string{"https://www.domain.com"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send create sidetree request: send operation request error")
		require.Nil(t, didResol)
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
			require.NoError(t, err)
			b, err := json.Marshal(didResolution{
				Context:     "https://www.w3.org/ns/did-resolution/v1",
				DIDDocument: bytes,
			})
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecUpdatePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		v := sidetree.New(sidetree.WithHTTPClient(&http.Client{}))

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return []string{serv.URL}, nil
			}), create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithAlsoKnownAs("https://first.blog.example"),
			create.WithAlsoKnownAs("https://second.blog.example"),
			create.WithPublicKey(&doc.PublicKey{
				ID:       "key1",
				Type:     doc.JWSVerificationKey2020,
				JWK:      jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: ed25519RecoveryPubKey}},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}),
			create.WithPublicKey(&doc.PublicKey{
				ID:       "key2",
				Type:     doc.JWSVerificationKey2020,
				JWK:      jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: ecPrivKey.Public()}},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}),
			create.WithService(&did.Service{
				ID:   "srv1",
				Type: "type",
				ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
					{
						URI:         "http://example.com",
						RoutingKeys: []string{"key1"},
					},
				}),
				Properties: map[string]interface{}{"priority": "1"},
			}))
		require.NoError(t, err)
		require.Equal(t, "did1", didResol.DIDDocument.ID)
	})

	t.Run("test error unmarshal result", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "{{")
			require.NoError(t, err)
		}))
		defer serv.Close()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecUpdatePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		v := sidetree.New(sidetree.WithHTTPClient(&http.Client{}))

		_, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return []string{serv.URL}, nil
			}), create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithService(&did.Service{
				ID:              "srv1",
				Type:            "type",
				ServiceEndpoint: model.NewDIDCommV1Endpoint("http://example.com"),
				Properties:      map[string]interface{}{"priority": "1"},
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse document resolution")
	})

	t.Run("test unsupported recovery public key type", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := sidetree.New()

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey("wrongkey"),
			create.WithUpdatePublicKey("wrongvalue"),
			create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get recovery key")
		require.Nil(t, didResol)
	})

	t.Run("test recovery public key empty", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := sidetree.New()

		didResol, err := v.CreateDID()
		require.Error(t, err)
		require.Contains(t, err.Error(), "recovery public key is required")
		require.Nil(t, didResol)
	})

	t.Run("test update public key empty", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v := sidetree.New()

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(pubKey),
			create.WithSidetreeEndpoint(func(bool) ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "update public key is required")
		require.Nil(t, didResol)
	})
}
