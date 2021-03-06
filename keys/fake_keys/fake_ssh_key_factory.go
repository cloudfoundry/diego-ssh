// Code generated by counterfeiter. DO NOT EDIT.
package fake_keys

import (
	"sync"

	"code.cloudfoundry.org/diego-ssh/keys"
)

type FakeSSHKeyFactory struct {
	NewKeyPairStub        func(int) (keys.KeyPair, error)
	newKeyPairMutex       sync.RWMutex
	newKeyPairArgsForCall []struct {
		arg1 int
	}
	newKeyPairReturns struct {
		result1 keys.KeyPair
		result2 error
	}
	newKeyPairReturnsOnCall map[int]struct {
		result1 keys.KeyPair
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeSSHKeyFactory) NewKeyPair(arg1 int) (keys.KeyPair, error) {
	fake.newKeyPairMutex.Lock()
	ret, specificReturn := fake.newKeyPairReturnsOnCall[len(fake.newKeyPairArgsForCall)]
	fake.newKeyPairArgsForCall = append(fake.newKeyPairArgsForCall, struct {
		arg1 int
	}{arg1})
	fake.recordInvocation("NewKeyPair", []interface{}{arg1})
	newKeyPairStubCopy := fake.NewKeyPairStub
	fake.newKeyPairMutex.Unlock()
	if newKeyPairStubCopy != nil {
		return newKeyPairStubCopy(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.newKeyPairReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeSSHKeyFactory) NewKeyPairCallCount() int {
	fake.newKeyPairMutex.RLock()
	defer fake.newKeyPairMutex.RUnlock()
	return len(fake.newKeyPairArgsForCall)
}

func (fake *FakeSSHKeyFactory) NewKeyPairCalls(stub func(int) (keys.KeyPair, error)) {
	fake.newKeyPairMutex.Lock()
	defer fake.newKeyPairMutex.Unlock()
	fake.NewKeyPairStub = stub
}

func (fake *FakeSSHKeyFactory) NewKeyPairArgsForCall(i int) int {
	fake.newKeyPairMutex.RLock()
	defer fake.newKeyPairMutex.RUnlock()
	argsForCall := fake.newKeyPairArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeSSHKeyFactory) NewKeyPairReturns(result1 keys.KeyPair, result2 error) {
	fake.newKeyPairMutex.Lock()
	defer fake.newKeyPairMutex.Unlock()
	fake.NewKeyPairStub = nil
	fake.newKeyPairReturns = struct {
		result1 keys.KeyPair
		result2 error
	}{result1, result2}
}

func (fake *FakeSSHKeyFactory) NewKeyPairReturnsOnCall(i int, result1 keys.KeyPair, result2 error) {
	fake.newKeyPairMutex.Lock()
	defer fake.newKeyPairMutex.Unlock()
	fake.NewKeyPairStub = nil
	if fake.newKeyPairReturnsOnCall == nil {
		fake.newKeyPairReturnsOnCall = make(map[int]struct {
			result1 keys.KeyPair
			result2 error
		})
	}
	fake.newKeyPairReturnsOnCall[i] = struct {
		result1 keys.KeyPair
		result2 error
	}{result1, result2}
}

func (fake *FakeSSHKeyFactory) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.newKeyPairMutex.RLock()
	defer fake.newKeyPairMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeSSHKeyFactory) recordInvocation(key string, args []interface{}) {
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

var _ keys.SSHKeyFactory = new(FakeSSHKeyFactory)
