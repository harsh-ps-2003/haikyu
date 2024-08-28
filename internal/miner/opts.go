package miner

import "github.com/sirupsen/logrus"

// Opts defines the configuration options for the miner.
type Opts struct {
	Logger       *logrus.Logger // Logger instance for miner-specific logging
	MaxBlockSize uint           // Maximum allowed block size in weight units
}
