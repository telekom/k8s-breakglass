// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"testing"

	"github.com/telekom/k8s-breakglass/pkg/utils"
)

// ---- ParsePageLimit ----

func TestParsePageLimit_Empty(t *testing.T) {
	limit, err := utils.ParsePageLimit("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limit != utils.DefaultPageSize {
		t.Errorf("expected %d, got %d", utils.DefaultPageSize, limit)
	}
}

func TestParsePageLimit_Valid(t *testing.T) {
	limit, err := utils.ParsePageLimit("50")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limit != 50 {
		t.Errorf("expected 50, got %d", limit)
	}
}

func TestParsePageLimit_Max(t *testing.T) {
	limit, err := utils.ParsePageLimit("500")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limit != utils.MaxPageSize {
		t.Errorf("expected %d, got %d", utils.MaxPageSize, limit)
	}
}

func TestParsePageLimit_ExceedsMax(t *testing.T) {
	_, err := utils.ParsePageLimit("501")
	if err == nil {
		t.Error("expected error for limit exceeding MaxPageSize")
	}
}

func TestParsePageLimit_Zero(t *testing.T) {
	_, err := utils.ParsePageLimit("0")
	if err == nil {
		t.Error("expected error for limit=0")
	}
}

func TestParsePageLimit_Negative(t *testing.T) {
	_, err := utils.ParsePageLimit("-1")
	if err == nil {
		t.Error("expected error for negative limit")
	}
}

func TestParsePageLimit_NonNumeric(t *testing.T) {
	_, err := utils.ParsePageLimit("abc")
	if err == nil {
		t.Error("expected error for non-numeric limit")
	}
}

// ---- ParseContinueToken / EncodeContinueToken ----

func TestParseContinueToken_Empty(t *testing.T) {
	offset, err := utils.ParseContinueToken("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if offset != 0 {
		t.Errorf("expected offset 0, got %d", offset)
	}
}

func TestParseContinueToken_RoundTrip(t *testing.T) {
	token := utils.EncodeContinueToken(100)
	offset, err := utils.ParseContinueToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if offset != 100 {
		t.Errorf("expected offset 100, got %d", offset)
	}
}

func TestParseContinueToken_InvalidBase64(t *testing.T) {
	_, err := utils.ParseContinueToken("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestParseContinueToken_ValidBase64NonInteger(t *testing.T) {
	// base64("hello") is a valid base64 string but decodes to non-integer
	_, err := utils.ParseContinueToken("aGVsbG8=")
	if err == nil {
		t.Error("expected error for base64-encoded non-integer")
	}
}

// ---- Paginate ----

func makeInts(n int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	return s
}

func TestPaginate_FirstPage(t *testing.T) {
	items := makeInts(250)
	page, nextToken := utils.Paginate(items, 100, 0)
	if len(page) != 100 {
		t.Errorf("expected 100 items, got %d", len(page))
	}
	if nextToken == "" {
		t.Error("expected non-empty nextToken")
	}
	// Verify the token decodes to 100
	offset, err := utils.ParseContinueToken(nextToken)
	if err != nil {
		t.Fatalf("token decode error: %v", err)
	}
	if offset != 100 {
		t.Errorf("expected next offset 100, got %d", offset)
	}
}

func TestPaginate_MiddlePage(t *testing.T) {
	items := makeInts(250)
	page, nextToken := utils.Paginate(items, 100, 100)
	if len(page) != 100 {
		t.Errorf("expected 100 items, got %d", len(page))
	}
	if nextToken == "" {
		t.Error("expected non-empty nextToken for middle page")
	}
	offset, err := utils.ParseContinueToken(nextToken)
	if err != nil {
		t.Fatalf("token decode error: %v", err)
	}
	if offset != 200 {
		t.Errorf("expected next offset 200, got %d", offset)
	}
}

func TestPaginate_LastPage_NoToken(t *testing.T) {
	items := makeInts(250)
	page, nextToken := utils.Paginate(items, 100, 200)
	if len(page) != 50 {
		t.Errorf("expected 50 items on last page, got %d", len(page))
	}
	if nextToken != "" {
		t.Errorf("expected empty nextToken on last page, got %q", nextToken)
	}
}

func TestPaginate_ExactPage_NoToken(t *testing.T) {
	items := makeInts(100)
	page, nextToken := utils.Paginate(items, 100, 0)
	if len(page) != 100 {
		t.Errorf("expected 100 items, got %d", len(page))
	}
	if nextToken != "" {
		t.Errorf("expected empty nextToken when items exactly fit one page, got %q", nextToken)
	}
}

func TestPaginate_OffsetBeyondEnd(t *testing.T) {
	items := makeInts(10)
	page, nextToken := utils.Paginate(items, 100, 20)
	if len(page) != 0 {
		t.Errorf("expected 0 items for offset beyond end, got %d", len(page))
	}
	if nextToken != "" {
		t.Errorf("expected empty nextToken, got %q", nextToken)
	}
}

func TestPaginate_EmptySlice(t *testing.T) {
	page, nextToken := utils.Paginate([]int{}, 100, 0)
	if len(page) != 0 {
		t.Errorf("expected 0 items for empty slice, got %d", len(page))
	}
	if nextToken != "" {
		t.Errorf("expected empty nextToken, got %q", nextToken)
	}
}

func TestPaginate_DefaultPaginationContinuation(t *testing.T) {
	// Verify the full walk of 250 items in pages of 100.
	items := makeInts(250)
	limit := utils.DefaultPageSize
	offset := 0
	pageCount := 0
	totalItems := 0

	for {
		page, nextToken := utils.Paginate(items, limit, offset)
		totalItems += len(page)
		pageCount++

		if nextToken == "" {
			break
		}
		var err error
		offset, err = utils.ParseContinueToken(nextToken)
		if err != nil {
			t.Fatalf("token decode error: %v", err)
		}
	}

	if pageCount != 3 {
		t.Errorf("expected 3 pages for 250 items with limit 100, got %d", pageCount)
	}
	if totalItems != 250 {
		t.Errorf("expected 250 total items, got %d", totalItems)
	}
}
