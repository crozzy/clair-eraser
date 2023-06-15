package main

import (
	"context"
	"time"

	"github.com/Azure/eraser/api/unversioned"
	"github.com/quay/clair-action/image"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
)

const (
	StatusFailed ScanStatus = iota
	StatusNonCompliant
	StatusOK
)

type TimeoutConfig struct {
	Total    unversioned.Duration `json:"total,omitempty"`
	PerImage unversioned.Duration `json:"perImage,omitempty"`
}

type ScanStatus int

type clair struct {
	indexer       *libindex.Libindex
	matcher       *libvuln.Libvuln
	timer         *time.Timer
	interpretConf *interpretation
}

type interpretation struct {
	VulnSeverity []claircore.Severity
}

func (c *clair) Scan(ctx context.Context, img unversioned.Image) (ScanStatus, error) {
	// TODO: Check cache for db file and don't bother with updates if so

	err := c.matcher.FetchUpdates(ctx)
	if err != nil {
		return StatusFailed, err
	}

	// img to Manifest

	m, err := image.Inspect(ctx, img.ImageID)
	if err != nil {
		return StatusFailed, err
	}

	ir, err := c.indexer.Index(ctx, m)
	if err != nil {
		return StatusFailed, err
	}

	vr, err := c.matcher.Scan(ctx, ir)
	if err != nil {
		return StatusFailed, err
	}
	if vulnerable := c.analyzeReport(vr); vulnerable {
		return StatusNonCompliant, nil
	}
	return StatusOK, nil
}

func (c *clair) analyzeReport(vr *claircore.VulnerabilityReport) bool {
	return false
}

func (s *clair) Timer() *time.Timer {
	return s.timer
}
