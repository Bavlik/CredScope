package cli

// Exit codes are part of CredScope's public CLI contract.
const (
	ExitOK             = 0
	ExitThreshold      = 1
	ExitUsage          = 2
	ExitMalformedInput = 3
	ExitInternal       = 4
)

type codedError struct {
	code   int
	err    error
	silent bool
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }
