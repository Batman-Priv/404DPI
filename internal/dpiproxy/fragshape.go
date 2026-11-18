package dpiproxy

import "time"

type natFragProfile struct {
	bigMin, bigMax     int
	smallMin, smallMax int
	smallProb          int
}

func newNaturalProfile() natFragProfile {
	return natFragProfile{
		bigMin:    64 + randIntN(64),
		bigMax:    192 + randIntN(320),
		smallMin:  1 + randIntN(4),
		smallMax:  8 + randIntN(24),
		smallProb: 15 + randIntN(20),
	}
}

func chunkDataNatural(data []byte, p natFragProfile) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		var size int
		if randIntN(100) < p.smallProb {
			size = p.smallMin + randIntN(max1(p.smallMax-p.smallMin+1))
		} else {
			size = p.bigMin + randIntN(max1(p.bigMax-p.bigMin+1))
		}
		if size > len(data) {
			size = len(data)
		}
		if size < 1 {
			size = 1
		}
		chunks = append(chunks, data[:size])
		data = data[size:]
	}
	return chunks
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func naturalDelay(maxMS int) time.Duration {
	if maxMS <= 0 {
		return 0
	}
	const samples = 3
	sum := 0
	for i := 0; i < samples; i++ {
		sum += randIntN(maxMS + 1)
	}
	return time.Duration(sum/samples) * time.Millisecond
}
