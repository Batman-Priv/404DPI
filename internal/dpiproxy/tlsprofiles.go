package dpiproxy

var chromeCipherOrder = []uint16{
	0x1301, 0x1302, 0x1303,
	0xc02b, 0xc02f, 0xc02c, 0xc030,
	0xcca9, 0xcca8,
	0xc013, 0xc014,
	0x009c, 0x009d, 0x002f, 0x0035,
}

var chromeExtOrder = []uint16{
	0,
	23,
	65281,
	10,
	11,
	35,
	16,
	5,
	13,
	18,
	51,
	45,
	43,
	27,
	21,
}

var firefoxCipherOrder = []uint16{
	0x1301, 0x1303, 0x1302,
	0xc02b, 0xc02f, 0xc02c, 0xc030,
	0xcca9, 0xcca8,
	0xc013, 0xc014,
	0x009c, 0x009d, 0x002f, 0x0035,
}

var firefoxExtOrder = []uint16{
	0, 23, 65281, 10, 11, 16, 5, 34, 51, 43, 13, 45, 28, 21,
}

var chromeCurveOrder = []uint16{0x001d, 0x0017, 0x0018}
var chromeSigAlgOrder = []uint16{
	0x0403, 0x0804, 0x0401,
	0x0503, 0x0805, 0x0501,
	0x0806, 0x0601,
}
var chromeALPNOrder = []string{"h2", "http/1.1"}

var firefoxCurveOrder = []uint16{0x001d, 0x0017, 0x0018, 0x0019}
var firefoxSigAlgOrder = []uint16{
	0x0403, 0x0503, 0x0603,
	0x0804, 0x0805, 0x0806,
	0x0401, 0x0501, 0x0601,
}
var firefoxALPNOrder = []string{"h2", "http/1.1"}

var safariCipherOrder = []uint16{
	0x1301, 0x1302, 0x1303,
	0xc02c, 0xc02b, 0xc030, 0xc02f,
	0xcca9, 0xcca8,
	0xc00a, 0xc009, 0xc014, 0xc013,
	0x009d, 0x009c, 0x0035, 0x002f,
}

var safariExtOrder = []uint16{
	0,
	23,
	65281,
	10,
	11,
	16,
	5,
	13,
	51,
	45,
	43,
	21,
}

var safariCurveOrder = []uint16{0x001d, 0x0017, 0x0018, 0x0019}
var safariSigAlgOrder = []uint16{
	0x0403, 0x0804, 0x0503, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
}
var safariALPNOrder = []string{"h2", "http/1.1"}

var edgeCipherOrder = chromeCipherOrder

var edgeExtOrder = []uint16{
	0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21,
}

var edgeCurveOrder = chromeCurveOrder
var edgeSigAlgOrder = chromeSigAlgOrder
var edgeALPNOrder = chromeALPNOrder

type profileContent struct {
	ciphers, exts, curves, sigAlgs []uint16
	alpn                           []string
}

func profileOrders(name string) (ciphers, exts []uint16) {
	pc := profileContentFor(name)
	return pc.ciphers, pc.exts
}

func profileContentFor(name string) profileContent {
	switch name {
	case "chrome":
		return profileContent{chromeCipherOrder, chromeExtOrder, chromeCurveOrder, chromeSigAlgOrder, chromeALPNOrder}
	case "firefox":
		return profileContent{firefoxCipherOrder, firefoxExtOrder, firefoxCurveOrder, firefoxSigAlgOrder, firefoxALPNOrder}
	case "safari":
		return profileContent{safariCipherOrder, safariExtOrder, safariCurveOrder, safariSigAlgOrder, safariALPNOrder}
	case "edge":
		return profileContent{edgeCipherOrder, edgeExtOrder, edgeCurveOrder, edgeSigAlgOrder, edgeALPNOrder}
	default:
		return profileContent{}
	}
}

func applyTLSProfile(ch *clientHelloMsg, profile string) {
	pc := profileContentFor(profile)
	if pc.ciphers == nil && pc.exts == nil {
		return
	}

	if len(pc.ciphers) > 0 {
		ch.CipherSuites = reorderCipherSuites(ch.CipherSuites, pc.ciphers)
	}

	for i := range ch.Extensions {
		switch ch.Extensions[i].Type {
		case 10:
			if len(pc.curves) > 0 {
				ch.Extensions[i].Data = reorderExtList16(ch.Extensions[i].Data, pc.curves)
			}
		case 13:
			if len(pc.sigAlgs) > 0 {
				ch.Extensions[i].Data = reorderExtList16(ch.Extensions[i].Data, pc.sigAlgs)
			}
		case 16:
			if len(pc.alpn) > 0 {
				ch.Extensions[i].Data = reorderALPN(ch.Extensions[i].Data, pc.alpn)
			}
		}
	}
	if len(pc.exts) > 0 {
		ch.Extensions = reorderExtensions(ch.Extensions, pc.exts)
	}
}

func reorderExtList16(data []byte, preference []uint16) []byte {
	vals := extList16(data)
	if len(vals) == 0 {
		return data
	}
	present := map[uint16]bool{}
	for _, v := range vals {
		present[v] = true
	}
	out := make([]uint16, 0, len(vals))
	used := map[uint16]bool{}
	for _, p := range preference {
		if present[p] {
			out = append(out, p)
			used[p] = true
		}
	}
	for _, v := range vals {
		if !used[v] {
			out = append(out, v)
			used[v] = true
		}
	}
	body := make([]byte, 0, 2+2*len(out))
	body = append(body, byte(len(out)*2>>8), byte(len(out)*2))
	for _, v := range out {
		body = append(body, byte(v>>8), byte(v))
	}
	return body
}

func reorderALPN(data []byte, preference []string) []byte {
	if len(data) < 2 {
		return data
	}
	listLen := int(data[0])<<8 | int(data[1])
	body := data[2:]
	if listLen > len(body) {
		listLen = len(body)
	}
	body = body[:listLen]

	var names []string
	for i := 0; i < len(body); {
		n := int(body[i])
		i++
		if i+n > len(body) {
			break
		}
		names = append(names, string(body[i:i+n]))
		i += n
	}
	if len(names) == 0 {
		return data
	}

	present := map[string]bool{}
	for _, n := range names {
		present[n] = true
	}
	var out []string
	used := map[string]bool{}
	for _, p := range preference {
		if present[p] {
			out = append(out, p)
			used[p] = true
		}
	}
	for _, n := range names {
		if !used[n] {
			out = append(out, n)
			used[n] = true
		}
	}

	newBody := make([]byte, 0, len(body))
	for _, n := range out {
		newBody = append(newBody, byte(len(n)))
		newBody = append(newBody, n...)
	}
	result := make([]byte, 0, 2+len(newBody))
	result = append(result, byte(len(newBody)>>8), byte(len(newBody)))
	result = append(result, newBody...)
	return result
}

func reorderCipherSuites(suites []byte, preference []uint16) []byte {
	present := map[uint16]bool{}
	for i := 0; i+1 < len(suites); i += 2 {
		present[uint16(suites[i])<<8|uint16(suites[i+1])] = true
	}

	out := make([]byte, 0, len(suites))
	used := map[uint16]bool{}
	for _, p := range preference {
		if present[p] {
			out = append(out, byte(p>>8), byte(p))
			used[p] = true
		}
	}
	for i := 0; i+1 < len(suites); i += 2 {
		v := uint16(suites[i])<<8 | uint16(suites[i+1])
		if !used[v] {
			out = append(out, suites[i], suites[i+1])
			used[v] = true
		}
	}
	return out
}

func reorderExtensions(exts []tlsExtension, preference []uint16) []tlsExtension {
	byType := map[uint16]tlsExtension{}
	for _, e := range exts {
		byType[e.Type] = e
	}

	out := make([]tlsExtension, 0, len(exts))
	used := map[uint16]bool{}
	for _, p := range preference {
		if e, ok := byType[p]; ok {
			out = append(out, e)
			used[p] = true
		}
	}
	for _, e := range exts {
		if !used[e.Type] {
			out = append(out, e)
			used[e.Type] = true
		}
	}
	return out
}
