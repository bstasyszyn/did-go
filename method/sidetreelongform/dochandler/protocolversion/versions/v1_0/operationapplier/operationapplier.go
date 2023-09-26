/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationapplier

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/did-go/method/sidetreelongform/dochandler/protocolversion/versions/v1_0/model"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/api/protocol"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/document"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/hashing"
	logfields "github.com/trustbloc/did-go/method/sidetreelongform/sidetree/internalx/log"
)

//go:generate counterfeiter -o operationparser.gen.go --fake-name MockOperationParser . OperationParser

var logger = log.New("sidetree-core-applier")

// Applier is an operation applier.
type Applier struct {
	protocol.Protocol
	OperationParser
	protocol.DocumentComposer
}

// OperationParser defines the functions for parsing operations.
type OperationParser interface {
	ValidateSuffixData(suffixData *model.SuffixDataModel) error
	ValidateDelta(delta *model.DeltaModel) error
	ParseCreateOperation(request []byte, anchor bool) (*model.Operation, error)
}

// New returns a new operation applier for the given protocol.
//
//nolint:gocritic
func New(p protocol.Protocol, parser OperationParser, dc protocol.DocumentComposer) *Applier {
	return &Applier{
		Protocol:         p,
		OperationParser:  parser,
		DocumentComposer: dc,
	}
}

// Apply applies the given anchored operation.
func (s *Applier) Apply(op *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	switch op.Type {
	case operation.TypeCreate:
		return s.applyCreateOperation(op, rm)
	default:
		return nil, fmt.Errorf("operation type not supported for process operation")
	}
}

func (s *Applier) applyCreateOperation(anchoredOp *operation.AnchoredOperation,
	rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	logger.Debug("Applying create operation", logfields.WithOperation(anchoredOp))

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	op, err := s.OperationParser.ParseCreateOperation(anchoredOp.OperationRequest, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse create operation in batch mode: %s", err.Error())
	}

	// from this point any error should advance recovery commitment
	result := &protocol.ResolutionModel{
		Doc:                            make(document.Document),
		CreatedTime:                    anchoredOp.TransactionTime,
		LastOperationTransactionTime:   anchoredOp.TransactionTime,
		LastOperationTransactionNumber: anchoredOp.TransactionNumber,
		LastOperationProtocolVersion:   anchoredOp.ProtocolVersion,
		VersionID:                      anchoredOp.CanonicalReference,
		CanonicalReference:             anchoredOp.CanonicalReference,
		EquivalentReferences:           anchoredOp.EquivalentReferences,
		RecoveryCommitment:             op.SuffixData.RecoveryCommitment,
		AnchorOrigin:                   op.SuffixData.AnchorOrigin,
		PublishedOperations:            rm.PublishedOperations,
	}

	// verify actual delta hash matches expected delta hash
	err = hashing.IsValidModelMultihash(op.Delta, op.SuffixData.DeltaHash)
	if err != nil {
		logger.Info("Delta doesn't match delta hash; set update commitment to nil and advance recovery commitment",
			log.WithError(err), logfields.WithSuffix(anchoredOp.UniqueSuffix), logfields.WithOperationType(string(anchoredOp.Type)),
			logfields.WithTransactionTime(anchoredOp.TransactionTime), logfields.WithTransactionNumber(anchoredOp.TransactionNumber))

		return result, nil
	}

	err = s.OperationParser.ValidateDelta(op.Delta)
	if err != nil {
		logger.Info("Parse delta failed; set update commitment to nil and advance recovery commitment",
			log.WithError(err), logfields.WithSuffix(op.UniqueSuffix), logfields.WithOperationType(string(op.Type)),
			logfields.WithTransactionTime(anchoredOp.TransactionTime), logfields.WithTransactionNumber(anchoredOp.TransactionNumber))

		return result, nil
	}

	result.UpdateCommitment = op.Delta.UpdateCommitment

	doc, err := s.ApplyPatches(make(document.Document), op.Delta.Patches)
	if err != nil {
		logger.Info("Apply patches failed; advance commitments",
			log.WithError(err), logfields.WithSuffix(anchoredOp.UniqueSuffix), logfields.WithOperationType(string(anchoredOp.Type)),
			logfields.WithTransactionTime(anchoredOp.TransactionTime), logfields.WithTransactionNumber(anchoredOp.TransactionNumber))

		return result, nil
	}

	result.Doc = doc

	return result, nil
}

func (s *Applier) verifyAnchoringTimeRange(from, until int64, anchor uint64) error {
	if from == 0 && until == 0 {
		// from and until are not specified - nothing to check
		return nil
	}

	if from > int64(anchor) {
		return fmt.Errorf("anchor from time is greater then anchoring time")
	}

	if s.getAnchorUntil(from, until) < int64(anchor) {
		return fmt.Errorf("anchor until time is less then anchoring time")
	}

	return nil
}

func (s *Applier) getAnchorUntil(from, until int64) int64 {
	if from != 0 && until == 0 {
		return from + int64(s.MaxDeltaSize)
	}

	return until
}
