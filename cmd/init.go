package main

import (
	"flag"
	"fmt"
	"os"

	"shard/internal/config"
)

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	cfgPath := fs.String("cfg", "shard.json", "Path to config file")
	_ = fs.Parse(args)

	if _, err := os.Stat(*cfgPath); err == nil {
		fmt.Fprintf(os.Stderr, "Warning: %s already exists and will be overwritten.\n", *cfgPath)
	}

	if err := config.WriteDefaultConfig(*cfgPath); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Default configuration written to %s\n", *cfgPath)
	return nil
}
