package path

import (
	"path/filepath"
	"runtime"
)

var (
	_, b, _, _      = runtime.Caller(0)
	Root            = filepath.Join(filepath.Dir(b), "../../")
	DBPath          = filepath.Join(Root, "test.db")
	MempoolDataPath = filepath.Join(Root, "mempool")
	OutFilePath     = filepath.Join(Root, "output.txt")

	LocalRoot            = filepath.Join(Root, "../")
	LocalDBPath          = filepath.Join(Root, "test.db")
	LocalMempoolDataPath = filepath.Join(Root, "mempool")
	LocalOutFilePath     = filepath.Join(Root, "output.txt")
)
