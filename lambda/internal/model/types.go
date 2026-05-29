package model

// VoteRequest is the JSON body of POST /vote.
// VoterID is a client-generated UUID — raw IP addresses are never received or stored.
type VoteRequest struct {
	PollID  string `json:"poll_id"`
	Option  string `json:"option"`
	VoterID string `json:"voter_id"`
}

// VoteResponse is returned on a successful vote.
type VoteResponse struct {
	Status string `json:"status"`
}

// PollResultItem mirrors the DynamoDB PollResults item shape.
type PollResultItem struct {
	PollID  string
	OptionA int64
	OptionB int64
	OptionC int64
	OptionD int64
}

// ResultsResponse is the payload of GET /results.
type ResultsResponse struct {
	PollID  string           `json:"poll_id"`
	Options map[string]int64 `json:"options"`
	Total   int64            `json:"total"`
}

// ErrorResponse is the standard error envelope returned on all error status codes.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains a machine-readable code and a human-readable message.
// Internal details (stack traces, resource names) must never appear here.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
