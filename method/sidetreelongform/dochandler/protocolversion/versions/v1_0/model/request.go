/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/patch"
)

// CreateRequest is the struct for create payload JCS.
type CreateRequest struct {
	// operation
	// Required: true
	Operation operation.Type `json:"type,omitempty"`

	// Suffix data object
	// Required: true
	SuffixData *SuffixDataModel `json:"suffixData,omitempty"`

	// Delta object
	// Required: true
	Delta *DeltaModel `json:"delta,omitempty"`
}

// SuffixDataModel is part of create request.
type SuffixDataModel struct {

	// Hash of the delta object (required)
	DeltaHash string `json:"deltaHash,omitempty"`

	// Commitment hash for the next recovery or deactivate operation (required)
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`

	// AnchorOrigin signifies the system(s) that know the most recent anchor for this DID (optional)
	AnchorOrigin interface{} `json:"anchorOrigin,omitempty"`

	// Type signifies the type of entity a DID represents (optional)
	Type string `json:"type,omitempty"`
}

// DeltaModel contains patch data (patches used for create, recover, update).
type DeltaModel struct {

	// Commitment hash for the next update operation
	UpdateCommitment string `json:"updateCommitment,omitempty"`

	// Patches defines document patches
	Patches []patch.Patch `json:"patches,omitempty"`
}
