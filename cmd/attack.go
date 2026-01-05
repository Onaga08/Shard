package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shard/internal/attack"
	"shard/internal/config"
)

func runAttack(args []string) error {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	cfgPath := fs.String("cfg", "shard.json", "Path to config file")
	outPath := fs.String("out", "", "Output JSONL file path (overrides config.output.jsonl_path)")
	fs.Parse(args)

	// Load config
	cfg, err := config.ReadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Determine output path
	output := cfg.Output.JSONLPath
	if *outPath != "" {
		output = *outPath
	}

	// Prepare runner
	runner, err := attack.NewRunner(cfg)
	if err != nil {
		return fmt.Errorf("runner init: %w", err)
	}

	// Context with cancel on Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n🛑 Interrupt received, stopping attack gracefully...")
		cancel()
	}()

	start := time.Now()
	fmt.Printf("🚀 Starting attack: rate=%d/s duration=%s concurrency=%d\n",
		cfg.Load.Rate, cfg.Load.Duration, cfg.Load.Concurrency)

	if err := runner.Run(ctx, output); err != nil {
		return fmt.Errorf("attack run: %w", err)
	}

	elapsed := time.Since(start)
	fmt.Printf("✅ Attack complete in %v, results written to %s\n", elapsed, output)
	return nil
}
