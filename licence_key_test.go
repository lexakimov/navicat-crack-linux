package main

import "testing"

func TestSerial17KnownVector(t *testing.T) {
	// Independent DES/3DES reference vector for salt 01 02 03.
	got, err := generateLicenseKey(17, "en", [3]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}

	if got != "NAVD-CFDY-Z4X3-YEBD" {
		t.Fatalf("serial = %q", got)
	}
}
