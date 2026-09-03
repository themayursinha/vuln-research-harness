package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/themayursinha/vuln-research-harness/internal/mcpreview"
)

func reviewMCPSchemaCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("review-mcp-schema requires exactly one tools.json path")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read tools: %w", err)
	}
	report, err := mcpreview.Review(data)
	if err != nil {
		return err
	}
	out, err := mcpreview.Encode(report)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}
