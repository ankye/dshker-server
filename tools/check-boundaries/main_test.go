package main

import "testing"

func TestStandaloneProductionDependencyBoundary(t *testing.T) {
	t.Chdir("../..")
	if err := check(); err != nil {
		t.Fatal("standalone boundary violated", err)
	}
}
