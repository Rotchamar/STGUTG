package ngapType

import "free5gclib/aper"

// Need to import "free5gclib/aper" if it uses "aper"

type RATRestrictionInformation struct {
	Value aper.BitString `aper:"sizeExt,sizeLB:8,sizeUB:8"`
}
