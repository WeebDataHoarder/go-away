package _interface

import (
	"encoding/json"
	"git.gammaspectra.live/git/go-away/utils/inline"
)

// Allocation is a combination of pointer location in WASM memory and size of it
type Allocation uint64

func NewAllocation(ptr, size uint32) Allocation {
	return Allocation((uint64(ptr) << uint64(32)) | uint64(size))
}

func (p Allocation) Pointer() uint32 {
	return uint32(p >> 32)
}
func (p Allocation) Size() uint32 {
	return uint32(p)
}

func MakeChallengeDecode(callback func(in MakeChallengeInput, out *MakeChallengeOutput), in Allocation) (out Allocation) {
	outStruct := &MakeChallengeOutput{}
	var inStruct MakeChallengeInput

	inData := PtrToBytes(in.Pointer(), in.Size())

	err := json.Unmarshal(inData, &inStruct)
	if err != nil {
		outStruct.Code = 500
		outStruct.Error = err.Error()
	} else {
		outStruct.Code = 200
		outStruct.Headers = make(inline.MIMEHeader)

		func() {
			// encapsulate err
			defer func() {
				if recovered := recover(); recovered != nil {
					if outStruct.Code == 200 {
						outStruct.Code = 500
					}
					if err, ok := recovered.(error); ok {
						outStruct.Error = err.Error()
					} else {
						outStruct.Error = "error"
					}
				}
			}()
			callback(inStruct, outStruct)
		}()
	}

	if len(outStruct.Headers) == 0 {
		outStruct.Headers = nil
	}

	outData, err := json.Marshal(outStruct)
	if err != nil {
		panic(err)
	}

	return NewAllocation(BytesToLeakedPtr(outData))
}

func VerifyChallengeDecode(callback func(in VerifyChallengeInput) VerifyChallengeOutput, in Allocation) (out VerifyChallengeOutput) {
	var inStruct VerifyChallengeInput

	inData := PtrToBytes(in.Pointer(), in.Size())

	err := json.Unmarshal(inData, &inStruct)
	if err != nil {
		return VerifyChallengeOutputError
	} else {
		func() {
			// encapsulate err
			defer func() {
				if recovered := recover(); recovered != nil {
					out = VerifyChallengeOutputError
				}
			}()
			out = callback(inStruct)
		}()
	}

	return out
}

type MakeChallengeInput struct {
	Key []byte

	Parameters map[string]string

	Headers inline.MIMEHeader
	Data    []byte
}

type MakeChallengeOutput struct {
	Data    []byte
	Code    int
	Headers inline.MIMEHeader
	Error   string
}

type VerifyChallengeInput struct {
	Key        []byte
	Parameters map[string]string

	Result []byte
}

type VerifyChallengeOutput uint64

// TODO: expand allowed values
const (
	VerifyChallengeOutputOK = VerifyChallengeOutput(iota)
	VerifyChallengeOutputFailed
	VerifyChallengeOutputError
)
