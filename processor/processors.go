package processor

import "github.com/pimmytrousers/malanalytics/processor/processors/static"

// Sources are the built in sources you can use
var Processors = []MalwareProcessor{
	&static.Static{},
}
