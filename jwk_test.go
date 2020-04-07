//go:generate go run $GOROOT/src/crypto/tls/generate_cert.go --rsa-bits 1024 --host 127.0.0.1,::1,localhost --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
package jose

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)


type MockRoundTripper struct {
	AssertFunc func(request* http.Request)
}

func (self MockRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	self.AssertFunc(request)
	return nil, nil
}

func TestBasicAuthorizationInjector_adds_basic_auth(t *testing.T)  {
	config := SecretProviderConfig{
		URI:             "",
		CacheEnabled:    false,
		CacheDuration:   0,
		Fingerprints:    nil,
		Cs:              nil,
		LocalCA:         "",
		AllowInsecure:   true,
		JWKClientId:     "test",
		JWKClientSecret: "secret",
	}
	injector := BasicAuthorizationInjector {
		roundTripper: MockRoundTripper{
			AssertFunc: func(request *http.Request) {
				actualAuth := request.Header.Get("Authorization")
				expectedAuth := "Basic dGVzdDpzZWNyZXQ="
				if actualAuth != expectedAuth {
					t.Errorf("Wrong Authorization. have: %s, want: %s", actualAuth, expectedAuth)
				}
			},
		},
		cfg: &config,
	}
	req, _ := http.NewRequest("GET", "www.w.com", new(bytes.Buffer))
	injector.RoundTrip(req)
}

func TestBasicAuthorizationInjector_does_not_add_basic_auth(t *testing.T)  {
	config := SecretProviderConfig{
		URI:             "",
		CacheEnabled:    false,
		CacheDuration:   0,
		Fingerprints:    nil,
		Cs:              nil,
		LocalCA:         "",
		AllowInsecure:   true,
		JWKClientId:     "",
		JWKClientSecret: "",
	}
	injector := BasicAuthorizationInjector {
		roundTripper: MockRoundTripper{
			AssertFunc: func(request *http.Request) {
				actualAuth := request.Header.Get("Authorization")
				if actualAuth != "" {
					t.Errorf("No Authorization wanted. have: %s", actualAuth)
				}
			},
		},
		cfg: &config,
	}
	req, _ := http.NewRequest("GET", "www.w.com", new(bytes.Buffer))
	injector.RoundTrip(req)
}

func TestJWK(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		t.Error(err)
		return
	}

	for _, tc := range []struct {
		Name string
		Alg  string
		ID   []string
	}{
		{
			Name: "public",
			ID:   []string{"2011-04-29"},
			Alg:  "RS256",
		},
		{
			Name: "public",
			ID:   []string{"1"},
		},
		{
			Name: "private",
			ID:   []string{"2011-04-29"},
			Alg:  "RS256",
		},
		{
			Name: "private",
			ID:   []string{"1"},
		},
		{
			Name: "symmetric",
			ID:   []string{"sim2"},
			Alg:  "HS256",
		},
	} {
		server := httptest.NewUnstartedServer(jwkEndpoint(tc.Name))
		defer server.Close()
		server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		server.StartTLS()

		secretProvidr, err := SecretProvider(SecretProviderConfig{URI: server.URL, LocalCA: "cert.pem"}, nil)
		if err != nil {
			t.Error(err)
		}
		for _, k := range tc.ID {
			key, err := secretProvidr.GetKey(k)
			if err != nil {
				t.Errorf("[%s] extracting the key %s: %s", tc.Name, k, err.Error())
			}
			if key.Algorithm != tc.Alg {
				t.Errorf("wrong alg. have: %s, want: %s", key.Algorithm, tc.Alg)
			}
		}
	}
}

func TestDialer_DialTLS_ko(t *testing.T) {
	d := NewDialer(SecretProviderConfig{})
	c, err := d.DialTLS("\t", "addr")
	if err == nil {
		t.Error(err)
	}
	if c != nil {
		t.Errorf("unexpected connection: %v", c)
	}
}

func Test_decodeFingerprints(t *testing.T) {
	_, err := DecodeFingerprints([]string{"not_encoded_message"})
	if err == nil {
		t.Error(err)
	}
}

func jwkEndpoint(name string) http.HandlerFunc {
	data, err := ioutil.ReadFile("./fixtures/" + name + ".json")
	return func(rw http.ResponseWriter, _ *http.Request) {
		if err != nil {
			rw.WriteHeader(500)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(data)
	}
}
