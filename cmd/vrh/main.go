package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/themayursinha/vuln-research-harness/internal/contract"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initCampaign(os.Args[2:])
	case "validate":
		err = validateCampaign(os.Args[2:])
	case "snapshot":
		err = snapshotCmd(os.Args[2:])
	case "families":
		err = familiesCmd(os.Args[2:])
	case "round":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "plan":
			err = roundPlanCmd(os.Args[3:])
		case "ingest":
			err = roundIngestCmd(os.Args[3:])
		default:
			usage()
			os.Exit(2)
		}
	case "repro":
		err = reproCmd(os.Args[2:])
	case "adversarial":
		err = validateCmd(os.Args[2:])
	case "verify-sandbox":
		err = verifySandboxCmd(os.Args[2:])
	case "campaign":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "status":
			err = campaignStatusCmd(os.Args[3:])
		default:
			usage()
			os.Exit(2)
		}
	case "version":
		fmt.Println("vrh 0.3.0")
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vrh:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  vrh init <campaign-dir>")
	fmt.Fprintln(os.Stderr, "  vrh validate <campaign.yaml>")
	fmt.Fprintln(os.Stderr, "  vrh snapshot <source-dir> <campaign-dir>")
	fmt.Fprintln(os.Stderr, "  vrh families <add|block|reopen|list> <campaign-dir> ...")
	fmt.Fprintln(os.Stderr, "  vrh round plan <campaign-dir> <max-workers>")
	fmt.Fprintln(os.Stderr, "  vrh round ingest <campaign-dir>")
	fmt.Fprintln(os.Stderr, "  vrh repro <cases.yaml> <campaign-dir>")
	fmt.Fprintln(os.Stderr, "  vrh verify-sandbox <campaign-dir>")
	fmt.Fprintln(os.Stderr, "  vrh adversarial <campaign-dir> <finding-id> <attempts.json> <summary>")
	fmt.Fprintln(os.Stderr, "  vrh campaign status <campaign-dir>")
	fmt.Fprintln(os.Stderr, "  vrh version")
}

func initCampaign(args []string) error {
	if len(args) != 1 {
		return errors.New("init requires exactly one campaign directory")
	}
	dir := args[0]
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create campaign directory: %w", err)
	}
	path := filepath.Join(dir, "campaign.yaml")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check campaign file: %w", err)
	}
	data, err := yaml.Marshal(contract.Template(filepath.Base(dir)))
	if err != nil {
		return fmt.Errorf("encode template: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write campaign: %w", err)
	}
	fmt.Println(path)
	return nil
}

func validateCampaign(args []string) error {
	if len(args) != 1 {
		return errors.New("validate requires exactly one campaign YAML path")
	}
	campaign, err := contract.Load(args[0])
	if err != nil {
		return err
	}
	if err := campaign.Validate(); err != nil {
		return err
	}
	fmt.Printf("valid campaign: %s\n", campaign.Name)
	return nil
}
