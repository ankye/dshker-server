package main

import "testing"

func TestSmokeRequiresExplicitProductionBinary(t *testing.T) {
	if err := run("", "report.json"); err == nil {
		t.Fatal("accepted missing production binary")
	}
	if err := run("relative-binary", "report.json"); err == nil {
		t.Fatal("accepted guessed production binary path")
	}
}
