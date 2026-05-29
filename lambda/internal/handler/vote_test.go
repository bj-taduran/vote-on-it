package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/bj-taduran/vote-on-it/internal/handler"
	"github.com/bj-taduran/vote-on-it/internal/model"
	"github.com/bj-taduran/vote-on-it/internal/repository"
)

// ── Mock service ──────────────────────────────────────────────────────────────

type mockPollService struct{ mock.Mock }

func (m *mockPollService) CastVote(ctx context.Context, req *model.VoteRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockPollService) GetResults(ctx context.Context, pollID string) (*model.ResultsResponse, error) {
	args := m.Called(ctx, pollID)
	res, _ := args.Get(0).(*model.ResultsResponse)
	return res, args.Error(1)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func voteEvent(body string) events.APIGatewayV2HTTPRequest {
	return events.APIGatewayV2HTTPRequest{
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method: http.MethodPost,
				Path:   "/vote",
			},
		},
		Body: body,
	}
}

func validVoteBody() string {
	b, _ := json.Marshal(map[string]string{
		"poll_id":  "poll-2026-001",
		"option":   "A",
		"voter_id": "550e8400-e29b-41d4-a716-446655440000",
	})
	return string(b)
}

func decodeBody(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(body), &m))
	return m
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestVoteHandler_Success(t *testing.T) {
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(nil)

	h := handler.NewVote(svc)
	resp, err := h.Handle(context.Background(), voteEvent(validVoteBody()))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp.Body)
	assert.Equal(t, "ok", body["status"])
	svc.AssertExpectations(t)
}

func TestVoteHandler_InvalidJSON(t *testing.T) {
	h := handler.NewVote(&mockPollService{})
	resp, err := h.Handle(context.Background(), voteEvent("not json"))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeBody(t, resp.Body)
	assert.Equal(t, "INVALID_JSON", body["error"].(map[string]interface{})["code"])
}

func TestVoteHandler_UnknownFields(t *testing.T) {
	body := `{"poll_id":"poll-001","option":"A","voter_id":"550e8400-e29b-41d4-a716-446655440000","extra":"bad"}`
	h := handler.NewVote(&mockPollService{})
	resp, err := h.Handle(context.Background(), voteEvent(body))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestVoteHandler_InvalidPollID(t *testing.T) {
	cases := []string{"", "POLL-001", "poll_001", "a", fmt.Sprintf("poll-%s", string(make([]byte, 55)))}
	for _, id := range cases {
		b, _ := json.Marshal(map[string]string{"poll_id": id, "option": "A", "voter_id": "550e8400-e29b-41d4-a716-446655440000"})
		h := handler.NewVote(&mockPollService{})
		resp, _ := h.Handle(context.Background(), voteEvent(string(b)))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "poll_id=%q", id)
	}
}

func TestVoteHandler_InvalidOption(t *testing.T) {
	for _, opt := range []string{"", "E", "a", "AB"} {
		b, _ := json.Marshal(map[string]string{"poll_id": "poll-001", "option": opt, "voter_id": "550e8400-e29b-41d4-a716-446655440000"})
		h := handler.NewVote(&mockPollService{})
		resp, _ := h.Handle(context.Background(), voteEvent(string(b)))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "option=%q", opt)
		body := decodeBody(t, resp.Body)
		assert.Equal(t, "INVALID_OPTION", body["error"].(map[string]interface{})["code"])
	}
}

func TestVoteHandler_InvalidVoterID(t *testing.T) {
	for _, id := range []string{"", "not-a-uuid", "550E8400-E29B-41D4-A716-446655440000"} {
		b, _ := json.Marshal(map[string]string{"poll_id": "poll-001", "option": "B", "voter_id": id})
		h := handler.NewVote(&mockPollService{})
		resp, _ := h.Handle(context.Background(), voteEvent(string(b)))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "voter_id=%q", id)
		body := decodeBody(t, resp.Body)
		assert.Equal(t, "INVALID_VOTER_ID", body["error"].(map[string]interface{})["code"])
	}
}

func TestVoteHandler_DuplicateVote(t *testing.T) {
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(repository.ErrDuplicateVote)

	h := handler.NewVote(svc)
	resp, err := h.Handle(context.Background(), voteEvent(validVoteBody()))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	body := decodeBody(t, resp.Body)
	assert.Equal(t, "VOTE_ALREADY_CAST", body["error"].(map[string]interface{})["code"])
}

func TestVoteHandler_WrappedDuplicateVote(t *testing.T) {
	// errors.Is must unwrap the duplicate sentinel even when wrapped.
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(fmt.Errorf("outer: %w", repository.ErrDuplicateVote))

	h := handler.NewVote(svc)
	resp, _ := h.Handle(context.Background(), voteEvent(validVoteBody()))

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestVoteHandler_ServiceError(t *testing.T) {
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(errors.New("unexpected db error"))

	h := handler.NewVote(svc)
	resp, err := h.Handle(context.Background(), voteEvent(validVoteBody()))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	body := decodeBody(t, resp.Body)
	assert.Equal(t, "INTERNAL_ERROR", body["error"].(map[string]interface{})["code"])
}

func TestVoteHandler_AllValidOptions(t *testing.T) {
	for _, opt := range []string{"A", "B", "C", "D"} {
		svc := &mockPollService{}
		svc.On("CastVote", mock.Anything, mock.Anything).Return(nil)

		b, _ := json.Marshal(map[string]string{"poll_id": "poll-001", "option": opt, "voter_id": "550e8400-e29b-41d4-a716-446655440000"})
		h := handler.NewVote(svc)
		resp, _ := h.Handle(context.Background(), voteEvent(string(b)))

		assert.Equal(t, http.StatusOK, resp.StatusCode, "option=%s", opt)
	}
}
