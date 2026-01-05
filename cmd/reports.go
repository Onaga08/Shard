package main

import (
	"flag"
	"fmt"
	"os"

	"shard/internal/stats"
)

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	inPath := fs.String("in", "results.jsonl", "Path to JSONL results file")
	fs.Parse(args)

	agg := stats.New()
	if err := agg.LoadJSONL(*inPath); err != nil {
		return fmt.Errorf("load results: %w", err)
	}

	agg.Report(os.Stdout)
	return nil
}
