package main

import (
	"os"

	"github.com/rs/zerolog"
)

func getLogger(debugLevel bool) *zerolog.Logger {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debugLevel {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	logger := zerolog.New(os.Stdout).With().Logger()

	return &logger
}
