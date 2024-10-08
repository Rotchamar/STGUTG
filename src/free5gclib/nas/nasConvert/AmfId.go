package nasConvert

import (
	"encoding/hex"
	"log"
)

func AmfIdToNas(amfId string) (amfRegionId uint8, amfSetId uint16, amfPointer uint8) {

	amfIdBytes, err := hex.DecodeString(amfId)
	if err != nil {
		log.Printf("amfId decode failed: %+v", err)
	}

	amfRegionId = uint8(amfIdBytes[0])
	amfSetId = uint16(amfIdBytes[1])<<2 + (uint16(amfIdBytes[2])&0x00c0)>>6
	amfPointer = uint8(amfIdBytes[2]) & 0x3f
	return
}
