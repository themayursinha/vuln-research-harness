package contract

import (
	"os"
	"testing"
)

func TestTemplateValidates(t *testing.T) {
	if err := Template("test-campaign").Validate(); err != nil {
		t.Fatalf("template should validate: %v", err)
	}
}

func TestValidateRejectsUnsafeCampaign(t *testing.T) {
	campaign := Template("test-campaign")
	campaign.Authorization.WrittenPermission = false
	campaign.Environment.Network = "open"
	campaign.Environment.SyntheticData = false
	campaign.Success.Evidence = nil

	if err := campaign.Validate(); err == nil {
		t.Fatal("unsafe campaign unexpectedly validated")
	}
}

func TestValidateRejectsUnpinnedContainerImage(t *testing.T) {
	campaign := Template("test-campaign")
	campaign.Environment.ContainerImage = "python:3.12"
	if err := campaign.Validate(); err == nil {
		t.Fatal("mutable container tag accepted")
	}
}

func TestLoadParsesYAML(t *testing.T) {
	path := t.TempDir() + "/campaign.yaml"
	content := "version: v1\nname: demo\ntarget:\n  name: target\n  source_snapshot: sha256:abc\n  source_path: ./target\nauthorization:\n  owner: owner\n  scope: local\n  written_permission: true\n  evidence: ticket-1\nattacker:\n  starting_privilege: unauthenticated\n  capabilities: [request]\nenvironment:\n  deployment: container\n  network: denied\n  isolation: rootless\n  container_image: localhost/vrh@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  synthetic_data: true\n  disposable: true\nsuccess:\n  impact: test\n  evidence: [repro]\ndiscovery:\n  source_first: true\n  history_restricted: true\n  internet_restricted: true\n"
	if err := writeTestFile(path, content); err != nil {
		t.Fatal(err)
	}
	campaign, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := campaign.Validate(); err != nil {
		t.Fatalf("loaded campaign should validate: %v", err)
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}
