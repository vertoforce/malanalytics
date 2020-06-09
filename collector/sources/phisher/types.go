package phisher

type PhishKit struct {
	Content     []byte
	FileName    string
	Size        int64
	ContentType string
	URLEntry    *PhishTankElement
}

type PhishTankElement struct {
	PhishID          string   `json:"phish_id"`
	URL              string   `json:"url"`
	PhishDetailURL   string   `json:"phish_detail_url"`
	SubmissionTime   string   `json:"submission_time"`
	VerificationTime string   `json:"verification_time"`
	Online           string   `json:"online"`
	Details          []Detail `json:"details"`
	Target           string   `json:"target"`
}

type Detail struct {
	IPAddress         string `json:"ip_address"`
	CIDRBlock         string `json:"cidr_block"`
	AnnouncingNetwork string `json:"announcing_network"`
	DetailTime        string `json:"detail_time"`
}
