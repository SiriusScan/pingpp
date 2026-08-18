package httpcol

import (
	"encoding/base64"
	"encoding/binary"
)

// faviconMMH3 is the Shodan-style signed murmur3 of newline-wrapped base64.
func faviconMMH3(data []byte) int32 {
	b64 := base64.StdEncoding.EncodeToString(data)
	var wrapped []byte
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		wrapped = append(wrapped, b64[i:end]...)
		wrapped = append(wrapped, '\n')
	}
	return int32(murmur3_32(wrapped, 0))
}

func murmur3_32(data []byte, seed uint32) uint32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	h := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
