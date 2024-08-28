package miner

import "github.com/sirupsen/logrus"

type Opts struct {
	Logger *logrus.Logger

	MaxBlockSize uint
}
