package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/bj-taduran/vote-on-it/internal/model"
	"github.com/bj-taduran/vote-on-it/internal/repository"
)

// maxVoteBodyBytes is the maximum accepted request body size for POST /vote.
// A fully-populated vote request is ~145 bytes; 512 gives ample room for whitespace.
const maxVoteBodyBytes = 512

var (
	// uuidV4Regex enforces lowercase RFC 4122 UUID v4:
	// version nibble must be 4; variant nibble must be 8, 9, a, or b.
	uuidV4Regex  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	validOptions = map[string]struct{}{"A": {}, "B": {}, "C": {}, "D": {}}
)

// VoteHandler handles POST /vote.
type VoteHandler struct {
	svc PollService
}

// NewVote returns a VoteHandler wired to the given service.
func NewVote(svc PollService) *VoteHandler {
	return &VoteHandler{svc: svc}
}

// Handle parses, validates, and processes a POST /vote request.
// Unknown JSON fields are rejected. All inputs are treated as hostile.
func (h *VoteHandler) Handle(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if len(event.Body) > maxVoteBodyBytes {
		return badRequest("REQUEST_TOO_LARGE", "Request body must not exceed 512 bytes."), nil
	}

	if !strings.HasPrefix(event.Headers["content-type"], "application/json") {
		return badRequest("INVALID_CONTENT_TYPE", "Content-Type must be application/json."), nil
	}

	var req model.VoteRequest
	dec := json.NewDecoder(strings.NewReader(event.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return badRequest("INVALID_JSON", "Request body is not valid JSON."), nil
	}

	if req.PollID == "" {
		return badRequest("MISSING_POLL_ID", "poll_id is required."), nil
	}
	if req.Option == "" {
		return badRequest("MISSING_OPTION", "option is required."), nil
	}
	if req.VoterID == "" {
		return badRequest("MISSING_VOTER_ID", "voter_id is required."), nil
	}

	if !pollIDRegex.MatchString(req.PollID) {
		return badRequest("INVALID_POLL_ID", "poll_id must match ^poll-[a-z0-9-]{1,50}$."), nil
	}
	if _, ok := validOptions[req.Option]; !ok {
		return badRequest("INVALID_OPTION", "option must be one of: A, B, C, D."), nil
	}
	if !uuidV4Regex.MatchString(req.VoterID) {
		return badRequest("INVALID_VOTER_ID", "voter_id must be a valid lowercase UUID v4."), nil
	}

	err := h.svc.CastVote(ctx, &req)
	switch {
	case errors.Is(err, repository.ErrDuplicateVote):
		return apiResponse(http.StatusConflict, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "VOTE_ALREADY_CAST", Message: "You have already voted."},
		}), nil
	case err != nil:
		log.Printf(`{"level":"ERROR","message":"cast_vote_failed"}`)
		return internalError(), nil
	}

	return apiResponse(http.StatusOK, model.VoteResponse{Status: "ok"}), nil
}
