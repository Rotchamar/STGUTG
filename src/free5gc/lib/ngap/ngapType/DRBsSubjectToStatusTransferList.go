package ngapType

// Need to import "free5gclib/aper" if it uses "aper"

/* Sequence of = 35, FULL Name = struct DRBsSubjectToStatusTransferList */
/* DRBsSubjectToStatusTransferItem */
type DRBsSubjectToStatusTransferList struct {
	List []DRBsSubjectToStatusTransferItem `aper:"valueExt,sizeLB:1,sizeUB:32"`
}
