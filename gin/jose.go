package gin

import (
	"bytes"
	"context"
	"fmt"
	auth0 "github.com/auth0-community/go-auth0"
	krakendjose "github.com/devopsfaith/krakend-jose"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	ginkrakend "github.com/devopsfaith/krakend/router/gin"
	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2/json"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

func HandlerFactory(hf ginkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginkrakend.HandlerFactory {
	return TokenSigner(TokenSignatureValidator(hf, logger, rejecterF), logger)
}

func TokenSigner(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		signerCfg, signer, err := krakendjose.NewSigner(cfg, nil)
		if err == krakendjose.ErrNoSignerCfg {
			logger.Info("JOSE: singer disabled for the endpoint", cfg.Endpoint)
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error("JOSE: unable to create the signer for the endpoint", cfg.Endpoint)
			logger.Error(err.Error())
			return hf(cfg, prxy)
		}

		logger.Info("JOSE: singer enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			proxyReq := ginkrakend.NewRequest(cfg.HeadersToPass)(c, cfg.QueryString)
			ctx, cancel := context.WithTimeout(c, cfg.Timeout)
			defer cancel()

			response, err := prxy(ctx, proxyReq)
			if err != nil {
				logger.Error("proxy response error:", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if response == nil {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if err := krakendjose.SignFields(signerCfg.KeysToSign, signer, response); err != nil {
				logger.Error(err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			for k, v := range response.Metadata.Headers {
				c.Header(k, v[0])
			}
			c.JSON(response.Metadata.StatusCode, response.Data)
		}
	}
}

func TokenSignatureValidator(hf ginkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		if rejecterF == nil {
			rejecterF = new(krakendjose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)

		handler := hf(cfg, prxy)
		scfg, err := krakendjose.GetSignatureConfig(cfg)
		if err == krakendjose.ErrNoValidatorCfg {
			logger.Info("JOSE: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: validator for %s: %s", cfg.Endpoint, err.Error()))
			return handler
		}

		validator, err := krakendjose.NewValidator(scfg, FromCookie)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		spcfg, err := krakendjose.BuildSecretProviderConfig(scfg)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		rolesHttpClient, err := krakendjose.GetHttpClient(spcfg, func(tripper http.RoundTripper) http.RoundTripper {
			return tripper
		})
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		getPayloadFromRolesUrl := func (incomingRequest *http.Request) ([]byte, error) {
			rolesRequest, err := http.NewRequest("GET", scfg.RolesUrl, new(bytes.Buffer))
			if err != nil {
				return nil, err
			}
			rolesRequest.Header.Add("Authorization", incomingRequest.Header.Get("Authorization"))
			response, err := rolesHttpClient.Do(rolesRequest)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()

			buffer, err := ioutil.ReadAll(response.Body)
			if err != nil {
				return nil, err
			}
			return buffer, nil
		}

		aclCheck, getClaims := SetupAclChecker(logger, scfg, getPayloadFromRolesUrl, validator)

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			token, err := validator.ValidateRequest(c.Request)
			if err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}

			claims, err := getClaims(c.Request, token)
			if err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}

			if rejecter.Reject(*claims) {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if !aclCheck(scfg.RolesKey, *claims, scfg.Roles) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			handler(c)
		}
	}
}

func SetupAclChecker(logger logging.Logger, scfg *krakendjose.SignatureConfig, getPayloadFromRolesUrl func(*http.Request) ([]byte, error), validator *auth0.JWTValidator) (func(string, map[string]interface{}, []string) bool, func(*http.Request, *jwt.JSONWebToken) (*map[string]interface{}, error)) {
	var aclCheck func(string, map[string]interface{}, []string) bool
	var getClaims func(*http.Request, *jwt.JSONWebToken) (*map[string]interface{}, error)

	if strings.Contains(scfg.RolesKey, ".") {
		aclCheck = func(roleKey string, claims map[string]interface{}, required []string) bool {
			return krakendjose.CanAccessNested(logger, roleKey, claims, required)
		}
	} else {
		aclCheck = func(roleKey string, claims map[string]interface{}, required []string) bool {
			return krakendjose.CanAccess(logger, roleKey, claims, required)
		}
	}

	if scfg.RolesUrl != "" {
		getClaims = func(request *http.Request, token *jwt.JSONWebToken) (*map[string]interface{}, error) {
			claims := map[string]interface{}{}
			buffer, err := getPayloadFromRolesUrl(request)
			if err != nil {
				return &claims, err
			}
			err = json.Unmarshal(buffer, &claims)
			return &claims, err
		}
	} else {
		getClaims = func(request *http.Request, token *jwt.JSONWebToken) (*map[string]interface{}, error) {
			claims := map[string]interface{}{}
			err := validator.Claims(request, token, &claims)
			return &claims, err
		}
	}
	return aclCheck, getClaims
}

func FromCookie(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if key == "" {
		key = "access_token"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(cookie.Value)
	}
}
