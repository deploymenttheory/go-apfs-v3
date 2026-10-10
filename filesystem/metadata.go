package filesystem

import (
	"io"
	"time"
)

// State distinguishes an observation from a field that was never captured.
type State uint8

const (
	Uncaptured State = iota
	Absent
	Present
)

// Observation retains explicit zero values, including mode 0000 and empty data.
type Observation[T any] struct {
	State State `json:"state"`
	Value T     `json:"value"`
}

// Metadata contains logical macOS values, independent of host enforcement.
// Mode uses native POSIX bits, not Go's differently arranged fs.FileMode bits.
type Metadata struct {
	Mode       Observation[uint32]    `json:"mode"`
	UID        Observation[uint32]    `json:"uid"`
	GID        Observation[uint32]    `json:"gid"`
	BSDFlags   Observation[uint32]    `json:"bsdFlags"`
	BirthTime  Observation[time.Time] `json:"birthTime"`
	ModifyTime Observation[time.Time] `json:"modifyTime"`
	ChangeTime Observation[time.Time] `json:"changeTime"`
	AccessTime Observation[time.Time] `json:"accessTime"`
}

// Value is a sized, independently owned attribute or fork reader. Close releases
// only this value. Opening a resource fork must not require buffering it in RAM.
type Value interface {
	io.ReaderAt
	io.Closer
	Size() int64
}

// Identity is meaningful only within its volume and historical view. It is not
// derived from a pathname; hard-link aliases have the same identity. Created
// workspace nodes use a workspace creation digest as Volume, a graph-local Object
// and View zero; their Created marker distinguishes them from native identities.
type Identity struct {
	Volume string `json:"volume"`
	Object uint64 `json:"object"`
	View   uint64 `json:"view"`
}
