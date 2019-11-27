// Code generated by counterfeiter. DO NOT EDIT.
package fake_authenticators

import (
	"regexp"
	"sync"

	"code.cloudfoundry.org/diego-ssh/authenticators"
	"golang.org/x/crypto/ssh"
)

type FakePasswordAuthenticator struct {
	AuthenticateStub        func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error)
	authenticateMutex       sync.RWMutex
	authenticateArgsForCall []struct {
		arg1 ssh.ConnMetadata
		arg2 []byte
	}
	authenticateReturns struct {
		result1 *ssh.Permissions
		result2 error
	}
	authenticateReturnsOnCall map[int]struct {
		result1 *ssh.Permissions
		result2 error
	}
	UserRegexpStub        func() *regexp.Regexp
	userRegexpMutex       sync.RWMutex
	userRegexpArgsForCall []struct {
	}
	userRegexpReturns struct {
		result1 *regexp.Regexp
	}
	userRegexpReturnsOnCall map[int]struct {
		result1 *regexp.Regexp
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakePasswordAuthenticator) Authenticate(arg1 ssh.ConnMetadata, arg2 []byte) (*ssh.Permissions, error) {
	var arg2Copy []byte
	if arg2 != nil {
		arg2Copy = make([]byte, len(arg2))
		copy(arg2Copy, arg2)
	}
	fake.authenticateMutex.Lock()
	ret, specificReturn := fake.authenticateReturnsOnCall[len(fake.authenticateArgsForCall)]
	fake.authenticateArgsForCall = append(fake.authenticateArgsForCall, struct {
		arg1 ssh.ConnMetadata
		arg2 []byte
	}{arg1, arg2Copy})
	fake.recordInvocation("Authenticate", []interface{}{arg1, arg2Copy})
	authenticateStubCopy := fake.AuthenticateStub
	fake.authenticateMutex.Unlock()
	if authenticateStubCopy != nil {
		return authenticateStubCopy(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.authenticateReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakePasswordAuthenticator) AuthenticateCallCount() int {
	fake.authenticateMutex.RLock()
	defer fake.authenticateMutex.RUnlock()
	return len(fake.authenticateArgsForCall)
}

func (fake *FakePasswordAuthenticator) AuthenticateCalls(stub func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error)) {
	fake.authenticateMutex.Lock()
	defer fake.authenticateMutex.Unlock()
	fake.AuthenticateStub = stub
}

func (fake *FakePasswordAuthenticator) AuthenticateArgsForCall(i int) (ssh.ConnMetadata, []byte) {
	fake.authenticateMutex.RLock()
	defer fake.authenticateMutex.RUnlock()
	argsForCall := fake.authenticateArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *FakePasswordAuthenticator) AuthenticateReturns(result1 *ssh.Permissions, result2 error) {
	fake.authenticateMutex.Lock()
	defer fake.authenticateMutex.Unlock()
	fake.AuthenticateStub = nil
	fake.authenticateReturns = struct {
		result1 *ssh.Permissions
		result2 error
	}{result1, result2}
}

func (fake *FakePasswordAuthenticator) AuthenticateReturnsOnCall(i int, result1 *ssh.Permissions, result2 error) {
	fake.authenticateMutex.Lock()
	defer fake.authenticateMutex.Unlock()
	fake.AuthenticateStub = nil
	if fake.authenticateReturnsOnCall == nil {
		fake.authenticateReturnsOnCall = make(map[int]struct {
			result1 *ssh.Permissions
			result2 error
		})
	}
	fake.authenticateReturnsOnCall[i] = struct {
		result1 *ssh.Permissions
		result2 error
	}{result1, result2}
}

func (fake *FakePasswordAuthenticator) UserRegexp() *regexp.Regexp {
	fake.userRegexpMutex.Lock()
	ret, specificReturn := fake.userRegexpReturnsOnCall[len(fake.userRegexpArgsForCall)]
	fake.userRegexpArgsForCall = append(fake.userRegexpArgsForCall, struct {
	}{})
	fake.recordInvocation("UserRegexp", []interface{}{})
	userRegexpStubCopy := fake.UserRegexpStub
	fake.userRegexpMutex.Unlock()
	if userRegexpStubCopy != nil {
		return userRegexpStubCopy()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.userRegexpReturns
	return fakeReturns.result1
}

func (fake *FakePasswordAuthenticator) UserRegexpCallCount() int {
	fake.userRegexpMutex.RLock()
	defer fake.userRegexpMutex.RUnlock()
	return len(fake.userRegexpArgsForCall)
}

func (fake *FakePasswordAuthenticator) UserRegexpCalls(stub func() *regexp.Regexp) {
	fake.userRegexpMutex.Lock()
	defer fake.userRegexpMutex.Unlock()
	fake.UserRegexpStub = stub
}

func (fake *FakePasswordAuthenticator) UserRegexpReturns(result1 *regexp.Regexp) {
	fake.userRegexpMutex.Lock()
	defer fake.userRegexpMutex.Unlock()
	fake.UserRegexpStub = nil
	fake.userRegexpReturns = struct {
		result1 *regexp.Regexp
	}{result1}
}

func (fake *FakePasswordAuthenticator) UserRegexpReturnsOnCall(i int, result1 *regexp.Regexp) {
	fake.userRegexpMutex.Lock()
	defer fake.userRegexpMutex.Unlock()
	fake.UserRegexpStub = nil
	if fake.userRegexpReturnsOnCall == nil {
		fake.userRegexpReturnsOnCall = make(map[int]struct {
			result1 *regexp.Regexp
		})
	}
	fake.userRegexpReturnsOnCall[i] = struct {
		result1 *regexp.Regexp
	}{result1}
}

func (fake *FakePasswordAuthenticator) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.authenticateMutex.RLock()
	defer fake.authenticateMutex.RUnlock()
	fake.userRegexpMutex.RLock()
	defer fake.userRegexpMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakePasswordAuthenticator) recordInvocation(key string, args []interface{}) {
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

var _ authenticators.PasswordAuthenticator = new(FakePasswordAuthenticator)
