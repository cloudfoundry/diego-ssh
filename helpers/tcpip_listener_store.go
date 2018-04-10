package helpers

import (
	"fmt"
	"net"
	"sync"
)

type TCPIPListenerStore struct {
	store map[string]net.Listener
	lock  sync.Mutex
}

func NewTCPIPListenerStore() *TCPIPListenerStore {
	return &TCPIPListenerStore{
		store: make(map[string]net.Listener),
		lock:  sync.Mutex{},
	}
}

func (t *TCPIPListenerStore) AddListener(addr string, ln net.Listener) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.store[addr] = ln
}

func (t *TCPIPListenerStore) RemoveListener(addr string) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	if ln, ok := t.store[addr]; ok {
		err := ln.Close()
		if err != nil {
			return err
		}
		delete(t.store, addr)
		return nil
	}
	return fmt.Errorf("Cannot remove listener addr %s since it doesn't exist", addr)
}

func (t *TCPIPListenerStore) RemoveAll() {
	t.lock.Lock()
	defer t.lock.Unlock()
	for k := range t.store {
		_ = t.store[k].Close()
		delete(t.store, k)
	}
}
