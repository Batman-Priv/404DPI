package dpiproxy

func extractSNI(handshake []byte) string {
	ch, err := parseClientHello(handshake)
	if err != nil {
		return ""
	}
	for _, ext := range ch.Extensions {
		if ext.Type != 0 {
			continue
		}
		data := ext.Data
		if len(data) < 2 {
			continue
		}
		pos := 2
		for pos+3 <= len(data) {
			nameType := data[pos]
			nameLen := int(data[pos+1])<<8 | int(data[pos+2])
			pos += 3
			if pos+nameLen > len(data) {
				break
			}
			if nameType == 0 {
				return string(data[pos : pos+nameLen])
			}
			pos += nameLen
		}
	}
	return ""
}
