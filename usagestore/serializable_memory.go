package usagestore

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const timeSzBytes = 15
const szMemSetHeaderV1 = 0xAE

type SerializableUsageSet map[[32]byte]memEntry

// Format:
// Header (1 byte)
// Size (n) (4 bytes)
// n memEntrys
//		key 32 bytes
// 		usage 4 bytes
//		created 15 bytes
// 		expires 15 bytes
// 		max 4 bytes
func (s SerializableUsageSet) Serialize() []byte {
	sz := 1 + 4 + (len(s) * (32 + 4 + timeSzBytes + timeSzBytes + 4))
	out := make([]byte, sz)
	out[0] = szMemSetHeaderV1
	binary.BigEndian.PutUint32(out[1:], uint32(len(s)))
	p := 5
	for k, entry := range s {
		copy(out[p:], k[:])
		p += 32
		binary.BigEndian.PutUint32(out[p:], uint32(entry.usage))
		p += 4
		created, _ := entry.created.In(time.UTC).MarshalBinary()
		expires, _ := entry.expire.In(time.UTC).MarshalBinary()
		copy(out[p:], created)
		p += len(created)
		copy(out[p:], expires)
		p += len(expires)
		binary.BigEndian.PutUint32(out[p:], uint32(entry.max))
		p += 4
	}
	return out
}

func UsageSet(source []byte) (SerializableUsageSet, error) {
	if len(source) == 0 {
		return make(SerializableUsageSet), nil
	}

	switch source[0] {
	case szMemSetHeaderV1:
		sz := int(binary.BigEndian.Uint32(source[1:]))
		if sz < 0 {
			return nil, errors.New("Invalid size on serialized usage set.")
		}
		m := make(SerializableUsageSet)
		p := 5
		for i := 0; i < sz; i++ {
			var key [32]byte
			copy(key[:], source[p:])
			p += 32
			var e memEntry
			e.usage = int(binary.BigEndian.Uint32(source[p:]))
			p += 4
			created := source[p : p+timeSzBytes]
			p += timeSzBytes
			expires := source[p : p+timeSzBytes]
			p += timeSzBytes
			e.max = int(binary.BigEndian.Uint32(source[p:]))
			p += 4
			if err := e.created.UnmarshalBinary(created); err != nil {
				return nil, err
			}
			if err := e.expire.UnmarshalBinary(expires); err != nil {
				return nil, err
			}
			m[key] = e
		}
		return m, nil
	default:
		return nil, errors.New("Invalid header on serialized usage set.")
	}
}

func (s SerializableUsageSet) Set(key string, value memEntry) {
	k := sha256.Sum256([]byte(key))
	s[k] = value
}

func (s SerializableUsageSet) Get(key string) (memEntry, bool) {
	k := sha256.Sum256([]byte(key))
	v, ok := s[k]
	return v, ok
}

func (s SerializableUsageSet) Cleanup() {
	for k, v := range s {
		if time.Now().After(v.expire) {
			delete(s, k)
		}
	}
}
