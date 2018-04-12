package helpers

import (
	"fmt"
	"net"
	"sync"
)

type ListenerStore struct {
	store map[string]net.Listener
	lock  sync.Mutex
}

func NewListenerStore() *ListenerStore {
	return &ListenerStore{
		store: make(map[string]net.Listener),
		lock:  sync.Mutex{},
	}
}

func (t *ListenerStore) AddListener(addr string, ln net.Listener) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.store[addr] = ln
}

func (t *ListenerStore) RemoveListener(addr string) error {
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
	return fmt.Errorf("RemoveListener error: addr %s doesn't exist", addr)
}

func (t *ListenerStore) ListAll() []string {
	t.lock.Lock()
	defer t.lock.Unlock()
	var l []string
	for k := range t.store {
		l = append(l, k)
	}
	return l
}

func (t *ListenerStore) RemoveAll() {
	t.lock.Lock()
	defer t.lock.Unlock()
	for k := range t.store {
		_ = t.store[k].Close()
		delete(t.store, k)
	}
}
