package main

import (
	"os"
	"testing"
)

func TestDetectAppMetadataFromFixtures(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		version string
		major   int
	}{
		{name: "Navicat 17", env: "NAVICAT_17_APP_ROOT", version: "17.3.10", major: 17},
		{name: "Navicat 18", env: "NAVICAT_18_APP_ROOT", version: "18.0.2", major: 18},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := os.Getenv(test.env)
			if root == "" {
				t.Skipf("set %s to an unpacked application", test.env)
			}

			metadata, err := detectAppMetadata(root)
			if err != nil {
				t.Fatal(err)
			}

			if metadata.version != test.version || metadata.major != test.major ||
				metadata.edition != "Premium" || metadata.language != "en" {
				t.Fatalf("unexpected application metadata: %+v", metadata)
			}
		})
	}
}
