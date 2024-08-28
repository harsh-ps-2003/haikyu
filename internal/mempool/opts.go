package mempool

import "github.com/sirupsen/logrus"

type Opts struct {
	Logger *logrus.Logger

	// mempoolConfig
	MaxMemPoolSize uint

	// tx config
	Dust      uint64
	MaxTxSize uint
}
