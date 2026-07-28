package main

import "testing"

func TestNewServer(t *testing.T) {
	s := newServer()
	if s == nil {
		t.Fatal("expected non-nil server")
	}
}
