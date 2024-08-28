package ierrors

import (
	"errors"
	"fmt"
)

type Err error

var (
	ErrFeeTooLow    Err = fmt.Errorf("fee too low")
	ErrInvalidTx    Err = fmt.Errorf("invalid transaction")
	ErrTxTooLarge   Err = fmt.Errorf("transaction too large")
	ErrAlreadySpent Err = fmt.Errorf("output already spent")
	ErrLowFee       Err = fmt.Errorf("fee too low")

	ErrInvalidSequence      = errors.New("sequence number too high")
	ErrInvalidOpCode        = errors.New("invalid opcode")
	ErrAsmAndScriptMismatch = errors.New("asm and script mismatch")
	ErrInvalidScript        = errors.New("invalid script")
	ErrInvalidAddress       = errors.New("invalid address")
	ErrChecksum             = errors.New("checksum mismatch")

	ErrUsingOpReturnAsInput = errors.New("using OP_RETURN as input")
	ErrScriptValidation     = errors.New("script validation error")

	ErrInvalidSignature     = errors.New("invalid signature")
	ErrRedeemScriptMismatch = errors.New("redeem script mismatch")
	ErrInvalidWitnessLength = errors.New("invalid witness length")
)
