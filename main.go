package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Azure/eraser/api/unversioned"
	template "github.com/Azure/eraser/pkg/scanners/template"
	"github.com/quay/clair-action/datastore"
	"github.com/quay/claircore/enricher/cvss"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	configPath = flag.String("config", "", "path to the configuration file")
	log        = logf.Log.WithName("scanner").WithValues("provider", "clair")
)

func main() {
	ctx := context.Background()
	flag.Parse()

	conf, err := parseConfig(*configPath)
	if err != nil {
		log.Error(err, "unable to parse config")
	}
	log.Info("config", "config", conf)
	// Fuck around getting the config in place (oh and define a config)
	// Interpret the bloody interpret

	// create image provider with custom values
	imageProvider := template.NewImageProvider(
		template.WithContext(context.Background()),
		template.WithMetrics(true), // should be from config
		template.WithDeleteScanFailedImages(conf.DeleteFailedImages),
		template.WithLogger(log),
	)

	// retrieve list of all non-running, non-excluded images from collector container
	allImages, err := imageProvider.ReceiveImages()
	if err != nil {
		log.Error(err, "unable to retrieve list of images from collector container")
		return
	}

	// init Clair
	clair, err := initClair(ctx, conf)

	// scan images with custom scanner
	nonCompliant, failedImages, err := scan(ctx, clair, allImages)
	if err != nil {
		log.Error(err, "unable to scan image with Clair")
	}

	// send images to eraser container
	if err := imageProvider.SendImages(nonCompliant, failedImages); err != nil {
		log.Error(err, "unable to send non-compliant images to eraser container")
		return
	}

	// complete scan
	if err := imageProvider.Finish(); err != nil {
		log.Error(err, "unable to complete scanner")
		return
	}
}

func initClair(ctx context.Context, conf *Config) (*clair, error) {
	c := &clair{
		timer: time.NewTimer(time.Duration(conf.Timeout.Total)),
	}
	cl := http.DefaultClient

	indexerOpts := &libindex.Options{
		Store:      datastore.NewLocalIndexerStore(),
		Locker:     newLocalLocker(),
		FetchArena: libindex.NewRemoteFetchArena(cl, os.TempDir()),
	}

	var err error
	if c.indexer, err = libindex.New(ctx, indexerOpts, http.DefaultClient); err != nil {
		return nil, fmt.Errorf("error creating Libindex: %v", err)
	}

	matcherStore, err := datastore.NewSQLiteMatcherStore(conf.CacheDir, true)

	matcherOpts := &libvuln.Options{
		Store:                    matcherStore,
		Locker:                   newLocalLocker(),
		DisableBackgroundUpdates: true,
		UpdateWorkers:            1,
		Enrichers: []driver.Enricher{
			&cvss.Enricher{},
		},
	}

	if c.matcher, err = libvuln.New(ctx, matcherOpts); err != nil {
		return nil, fmt.Errorf("error creating Libvuln: %v", err)
	}
	return c, nil
}

func scan(ctx context.Context, c *clair, allImages []unversioned.Image) ([]unversioned.Image, []unversioned.Image, error) {
	vulnerableImages := make([]unversioned.Image, 0, len(allImages))
	failedImages := make([]unversioned.Image, 0, len(allImages))
	// track total scan job time

	for idx, img := range allImages {
		select {
		case <-c.Timer().C:
			failedImages = append(failedImages, allImages[idx:]...)
			return vulnerableImages, failedImages, errors.New("image scan total timeout exceeded")
		default:
			// Logs scan failures
			status, err := c.Scan(ctx, img)
			if err != nil {
				failedImages = append(failedImages, img)
				log.Error(err, "scan failed")
				continue
			}

			switch status {
			case StatusNonCompliant:
				log.Info("vulnerable image found", "img", img)
				vulnerableImages = append(vulnerableImages, img)
			case StatusFailed:
				failedImages = append(failedImages, img)
			}
		}
	}

	return vulnerableImages, failedImages, nil
}
