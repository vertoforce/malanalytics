package enrichment

import "github.com/pimmytrousers/malanalytics/enrichment/services/static"

var EnrichmentServices = []EnrichmentService{
	&static.Static{},
}
