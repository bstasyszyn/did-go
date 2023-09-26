// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree/api/protocol"
)

type DocumentValidator struct {
	IsValidOriginalDocumentStub        func([]byte) error
	isValidOriginalDocumentMutex       sync.RWMutex
	isValidOriginalDocumentArgsForCall []struct {
		arg1 []byte
	}
	isValidOriginalDocumentReturns struct {
		result1 error
	}
	isValidOriginalDocumentReturnsOnCall map[int]struct {
		result1 error
	}
	IsValidPayloadStub        func([]byte) error
	isValidPayloadMutex       sync.RWMutex
	isValidPayloadArgsForCall []struct {
		arg1 []byte
	}
	isValidPayloadReturns struct {
		result1 error
	}
	isValidPayloadReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *DocumentValidator) IsValidOriginalDocument(arg1 []byte) error {
	var arg1Copy []byte
	if arg1 != nil {
		arg1Copy = make([]byte, len(arg1))
		copy(arg1Copy, arg1)
	}
	fake.isValidOriginalDocumentMutex.Lock()
	ret, specificReturn := fake.isValidOriginalDocumentReturnsOnCall[len(fake.isValidOriginalDocumentArgsForCall)]
	fake.isValidOriginalDocumentArgsForCall = append(fake.isValidOriginalDocumentArgsForCall, struct {
		arg1 []byte
	}{arg1Copy})
	fake.recordInvocation("IsValidOriginalDocument", []interface{}{arg1Copy})
	fake.isValidOriginalDocumentMutex.Unlock()
	if fake.IsValidOriginalDocumentStub != nil {
		return fake.IsValidOriginalDocumentStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.isValidOriginalDocumentReturns
	return fakeReturns.result1
}

func (fake *DocumentValidator) IsValidOriginalDocumentCallCount() int {
	fake.isValidOriginalDocumentMutex.RLock()
	defer fake.isValidOriginalDocumentMutex.RUnlock()
	return len(fake.isValidOriginalDocumentArgsForCall)
}

func (fake *DocumentValidator) IsValidOriginalDocumentCalls(stub func([]byte) error) {
	fake.isValidOriginalDocumentMutex.Lock()
	defer fake.isValidOriginalDocumentMutex.Unlock()
	fake.IsValidOriginalDocumentStub = stub
}

func (fake *DocumentValidator) IsValidOriginalDocumentArgsForCall(i int) []byte {
	fake.isValidOriginalDocumentMutex.RLock()
	defer fake.isValidOriginalDocumentMutex.RUnlock()
	argsForCall := fake.isValidOriginalDocumentArgsForCall[i]
	return argsForCall.arg1
}

func (fake *DocumentValidator) IsValidOriginalDocumentReturns(result1 error) {
	fake.isValidOriginalDocumentMutex.Lock()
	defer fake.isValidOriginalDocumentMutex.Unlock()
	fake.IsValidOriginalDocumentStub = nil
	fake.isValidOriginalDocumentReturns = struct {
		result1 error
	}{result1}
}

func (fake *DocumentValidator) IsValidOriginalDocumentReturnsOnCall(i int, result1 error) {
	fake.isValidOriginalDocumentMutex.Lock()
	defer fake.isValidOriginalDocumentMutex.Unlock()
	fake.IsValidOriginalDocumentStub = nil
	if fake.isValidOriginalDocumentReturnsOnCall == nil {
		fake.isValidOriginalDocumentReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.isValidOriginalDocumentReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *DocumentValidator) IsValidPayload(arg1 []byte) error {
	var arg1Copy []byte
	if arg1 != nil {
		arg1Copy = make([]byte, len(arg1))
		copy(arg1Copy, arg1)
	}
	fake.isValidPayloadMutex.Lock()
	ret, specificReturn := fake.isValidPayloadReturnsOnCall[len(fake.isValidPayloadArgsForCall)]
	fake.isValidPayloadArgsForCall = append(fake.isValidPayloadArgsForCall, struct {
		arg1 []byte
	}{arg1Copy})
	fake.recordInvocation("IsValidPayload", []interface{}{arg1Copy})
	fake.isValidPayloadMutex.Unlock()
	if fake.IsValidPayloadStub != nil {
		return fake.IsValidPayloadStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.isValidPayloadReturns
	return fakeReturns.result1
}

func (fake *DocumentValidator) IsValidPayloadCallCount() int {
	fake.isValidPayloadMutex.RLock()
	defer fake.isValidPayloadMutex.RUnlock()
	return len(fake.isValidPayloadArgsForCall)
}

func (fake *DocumentValidator) IsValidPayloadCalls(stub func([]byte) error) {
	fake.isValidPayloadMutex.Lock()
	defer fake.isValidPayloadMutex.Unlock()
	fake.IsValidPayloadStub = stub
}

func (fake *DocumentValidator) IsValidPayloadArgsForCall(i int) []byte {
	fake.isValidPayloadMutex.RLock()
	defer fake.isValidPayloadMutex.RUnlock()
	argsForCall := fake.isValidPayloadArgsForCall[i]
	return argsForCall.arg1
}

func (fake *DocumentValidator) IsValidPayloadReturns(result1 error) {
	fake.isValidPayloadMutex.Lock()
	defer fake.isValidPayloadMutex.Unlock()
	fake.IsValidPayloadStub = nil
	fake.isValidPayloadReturns = struct {
		result1 error
	}{result1}
}

func (fake *DocumentValidator) IsValidPayloadReturnsOnCall(i int, result1 error) {
	fake.isValidPayloadMutex.Lock()
	defer fake.isValidPayloadMutex.Unlock()
	fake.IsValidPayloadStub = nil
	if fake.isValidPayloadReturnsOnCall == nil {
		fake.isValidPayloadReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.isValidPayloadReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *DocumentValidator) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.isValidOriginalDocumentMutex.RLock()
	defer fake.isValidOriginalDocumentMutex.RUnlock()
	fake.isValidPayloadMutex.RLock()
	defer fake.isValidPayloadMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *DocumentValidator) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ protocol.DocumentValidator = new(DocumentValidator)
