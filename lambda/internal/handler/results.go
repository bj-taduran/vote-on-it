package handler

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/events"
)

const defaultPollID = "poll-2026-001"

// ResultsHandler handles GET /results.
type ResultsHandler struct {
	svc PollService
}

// NewResults returns a ResultsHandler wired to the given service.
func NewResults(svc PollService) *ResultsHandler {
	return &ResultsHandler{svc: svc}
}

// Handle fetches and returns current vote percentages.
// poll_id is read from query parameters; falls back to defaultPollID.
func (h *ResultsHandler) Handle(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	pollID := event.QueryStringParameters["poll_id"]
	if pollID == "" {
		pollID = defaultPollID
	}
	if !pollIDRegex.MatchString(pollID) {
		return badRequest("INVALID_POLL_ID", "poll_id must match ^poll-[a-z0-9-]{1,50}$."), nil
	}

	results, err := h.svc.GetResults(ctx, pollID)
	if err != nil {
		log.Printf(`{"level":"ERROR","message":"get_results_failed"}`)
		return internalError(), nil
	}

	return apiResponse(200, results), nil
}
