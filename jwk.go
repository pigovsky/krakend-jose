package jose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	auth0 "github.com/auth0-community/go-auth0"
)

type SecretProviderConfig struct {
	URI           string
	CacheEnabled  bool
	CacheDuration uint32
	Fingerprints  [][]byte
	Cs            []uint16
	LocalCA       string
	AllowInsecure bool
	JWKClientId     string
	JWKClientSecret string
}

var (
	ErrInsecureJWKSource = errors.New("JWK client is using an insecure connection to the JWK service")
	ErrPinnedKeyNotFound = errors.New("JWK client did not find a pinned key")
)

type BasicAuthorizationInjector struct {
	roundTripper http.RoundTripper
	cfg *SecretProviderConfig
}

func (self BasicAuthorizationInjector) RoundTrip(request *http.Request) (*http.Response, error) {
	if self.cfg.JWKClientId != "" || self.cfg.JWKClientSecret != "" {
		token := fmt.Sprintf("%s:%s", self.cfg.JWKClientId, self.cfg.JWKClientSecret)
		encodedToken := base64.StdEncoding.EncodeToString([]byte(token))
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedToken))
	}
	return self.roundTripper.RoundTrip(request)
}

func GetHttpClient(cfg *SecretProviderConfig, roundTripInjector func(http.RoundTripper) http.RoundTripper) (*http.Client, error) {
	if len(cfg.Cs) == 0 {
		cfg.Cs = DefaultEnabledCipherSuites
	}

	dialer := NewDialer(*cfg)

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if cfg.LocalCA != "" {
		certs, err := ioutil.ReadFile(cfg.LocalCA)
		if err != nil {
			return nil, fmt.Errorf("Failed to append %q to RootCAs: %v", cfg.LocalCA, err)
		}
		rootCAs.AppendCertsFromPEM(certs)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			CipherSuites:       cfg.Cs,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.AllowInsecure,
			RootCAs:            rootCAs,
		},
	}

	if len(cfg.Fingerprints) > 0 {
		transport.DialTLS = dialer.DialTLS
	}

	httpClient := &http.Client{
		Transport: roundTripInjector(transport),
	}
	return httpClient, nil
}

func SecretProvider(cfg SecretProviderConfig, te auth0.RequestTokenExtractor) (*auth0.JWKClient, error) {
	httpClient, err := GetHttpClient(&cfg, func(transport http.RoundTripper) http.RoundTripper {
		return &BasicAuthorizationInjector{roundTripper: transport, cfg: &cfg}
	})
	if err != nil {
		return nil, err
	}
	opts := auth0.JWKClientOptions{
		URI:    cfg.URI,
		Client: httpClient,
	}

	if !cfg.CacheEnabled {
		return auth0.NewJWKClient(opts, te), nil
	}
	var cacheDuration time.Duration
	cacheDuration = time.Duration(cfg.CacheDuration) * time.Second
	// Set default duration to 15 minute
	if cacheDuration == 0 {
		cacheDuration = 15 * time.Minute
	}
	keyCacher := auth0.NewMemoryKeyCacher(cacheDuration, 100)
	return auth0.NewJWKClientWithCache(opts, te, keyCacher), nil
}

func DecodeFingerprints(in []string) ([][]byte, error) {
	out := make([][]byte, len(in))
	for i, f := range in {
		r, err := base64.URLEncoding.DecodeString(f)
		if err != nil {
			return out, fmt.Errorf("decoding fingerprint #%d: %s", i, err.Error())
		}
		out[i] = r
	}
	return out, nil
}

func NewDialer(cfg SecretProviderConfig) *Dialer {
	return &Dialer{
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		},
		fingerprints: cfg.Fingerprints,
	}
}

type Dialer struct {
	dialer             *net.Dialer
	fingerprints       [][]byte
	skipCAVerification bool
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}

func (d *Dialer) DialTLS(network, addr string) (net.Conn, error) {
	c, err := tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: d.skipCAVerification})
	if err != nil {
		return nil, err
	}
	connstate := c.ConnectionState()
	keyPinValid := false
	for _, peercert := range connstate.PeerCertificates {
		der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		hash := sha256.Sum256(der)
		if err != nil {
			log.Fatal(err)
		}
		for _, fingerprint := range d.fingerprints {
			if bytes.Compare(hash[0:], fingerprint) == 0 {
				keyPinValid = true
				break
			}
		}
	}
	if keyPinValid == false {
		return nil, ErrPinnedKeyNotFound
	}
	return c, nil
}

var (
	// DefaultEnabledCipherSuites is a collection of secure cipher suites to use
	DefaultEnabledCipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
)
