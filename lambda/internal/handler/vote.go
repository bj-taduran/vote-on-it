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

var (
	// uuidRegex accepts lowercase UUID v4. The client must generate a proper UUID.
	uuidRegex    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
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
	var req model.VoteRequest
	dec := json.NewDecoder(strings.NewReader(event.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return badRequest("INVALID_JSON", "Request body is not valid JSON."), nil
	}

	if !pollIDRegex.MatchString(req.PollID) {
		return badRequest("INVALID_POLL_ID", "poll_id must match ^poll-[a-z0-9-]{1,50}$."), nil
	}
	if _, ok := validOptions[req.Option]; !ok {
		return badRequest("INVALID_OPTION", "option must be one of: A, B, C, D."), nil
	}
	if !uuidRegex.MatchString(req.VoterID) {
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
