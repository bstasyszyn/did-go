/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package sidetree implements sidetree client
package sidetree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	docdid "github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/method/sidetreelongform/dochandler/protocolversion/versions/v1_0/clientx"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/commitment"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/doc"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/option/create"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/util/pubkey"
)

const (
	defaultHashAlgorithm = 18
	logPrefix            = " [did-go/method/sidetree] "
)

var errorLogger = log.New(os.Stderr, logPrefix, log.Ldate|log.Ltime|log.LUTC)
var debugLogger = log.New(io.Discard, logPrefix, log.Ldate|log.Ltime|log.LUTC)

type authTokenProvider interface {
	AuthToken() (string, error)
}

// GetEndpointsFunc retrieves sidetree endpoints.
type GetEndpointsFunc = func(disableCache bool) ([]string, error)

// Client sidetree client.
type Client struct {
	client            *http.Client
	authToken         string
	authTokenProvider authTokenProvider
	sendRequest       func(req []byte, getEndpoints GetEndpointsFunc) ([]byte, error)
}

// New return sidetree client.
func New(opts ...Option) *Client {
	c := &Client{client: &http.Client{}}

	c.sendRequest = c.defaultSendRequest

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CreateDID create did doc.
func (c *Client) CreateDID(opts ...create.Option) (*docdid.DocResolution, error) {
	createDIDOpts := &create.Opts{MultiHashAlgorithm: defaultHashAlgorithm}
	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	err := validateCreateReq(createDIDOpts)
	if err != nil {
		return nil, err
	}

	req, err := buildCreateRequest(createDIDOpts.MultiHashAlgorithm, createDIDOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to build sidetree request: %w", err)
	}

	responseBytes, err := c.sendRequest(req, createDIDOpts.GetEndpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to send create sidetree request: %w", err)
	}

	documentResolution, err := docdid.ParseDocumentResolution(responseBytes)
	if err != nil {
		if !errors.Is(err, docdid.ErrDIDDocumentNotExist) {
			return nil, fmt.Errorf("failed to parse document resolution: %w", err)
		}

		errorLogger.Printf("failed to parse document resolution %v", err)
	} else {
		return documentResolution, nil
	}

	didDoc, err := docdid.ParseDocument(responseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse did document: %w", err)
	}

	return &docdid.DocResolution{DIDDocument: didDoc}, nil
}

func validateCreateReq(createDIDOpts *create.Opts) error {
	if createDIDOpts.RecoveryPublicKey == nil {
		return fmt.Errorf("recovery public key is required")
	}

	if createDIDOpts.UpdatePublicKey == nil {
		return fmt.Errorf("update public key is required")
	}

	return nil
}

// buildCreateRequest request builder for sidetree public DID creation.
func buildCreateRequest(multiHashAlgorithm uint, createDIDOpts *create.Opts) ([]byte, error) {
	didDoc := &doc.Doc{
		PublicKey:   createDIDOpts.PublicKeys,
		Service:     createDIDOpts.Services,
		AlsoKnownAs: createDIDOpts.AlsoKnownAs,
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %w", err)
	}

	recoveryKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.RecoveryPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get recovery key : %w", err)
	}

	updateKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.UpdatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get update key : %w", err)
	}

	recoveryCommitment, err := commitment.GetCommitment(recoveryKey, multiHashAlgorithm)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.GetCommitment(updateKey, multiHashAlgorithm)
	if err != nil {
		return nil, err
	}

	createRequestInfo := &clientx.CreateRequestInfo{
		OpaqueDocument:     string(docBytes),
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      multiHashAlgorithm,
	}

	if createDIDOpts.AnchorOrigin != "" {
		createRequestInfo.AnchorOrigin = createDIDOpts.AnchorOrigin
	}

	req, err := clientx.NewCreateRequest(createRequestInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create sidetree request: %w", err)
	}

	return req, nil
}

func (c *Client) defaultSendRequest(req []byte, getEndpoints GetEndpointsFunc) ([]byte, error) {
	if getEndpoints == nil {
		return nil, fmt.Errorf("sidetree get endpoints func is required")
	}

	responseBytes, err := c.doSendRequest(req, getEndpoints, false)
	if err != nil {
		errorLogger.Printf("Error sending request. Trying again with endpoint cache disabled.: %s", err)

		responseBytes, err = c.doSendRequest(req, getEndpoints, true)
		if err != nil {
			return nil, fmt.Errorf("sidetree get endpoints: %w", err)
		}
	}

	return responseBytes, nil
}

func (c *Client) doSendRequest(req []byte, getEndpoints GetEndpointsFunc, disableCache bool) ([]byte, error) {
	endpoints, err := getEndpoints(disableCache)
	if err != nil {
		return nil, fmt.Errorf("sidetree get endpoints: %w", err)
	}

	debugLogger.Printf("Got sidetree endpoints: %s", endpoints)

	// TODO add logic for using different sidetree endpoint
	// for now will use the first one
	endpointURL := endpoints[0]

	httpReq, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, endpointURL, bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	authToken := c.authToken

	if c.authTokenProvider != nil {
		v, errToken := c.authTokenProvider.AuthToken()
		if errToken != nil {
			return nil, errToken
		}

		authToken = "Bearer " + v
	}

	if authToken != "" {
		httpReq.Header.Add("Authorization", authToken)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		errorLogger.Printf("Failed to close response body: %v", e)
	}
}
