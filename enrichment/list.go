package enrichment

import "github.com/pimmytrousers/melk/enrichment/services/static"

var EnrichmentServices = []EnrichmentService{
	&static.Static{},
}
