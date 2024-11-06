package main

import (
	"flag"
	"fmt"
	stdlog "log"

	"go.uber.org/zap"

	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/api"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/system"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook"
	accessreview "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review"
)

func main() {
	debug := true
	flag.BoolVar(&debug, "debug", false, "enables debug mode")
	flag.Parse()

	log := setupLogger(debug)
	log.With("version", system.Version).Info("Starting breakglass api")

	config, err := config.Load()
	if err != nil {
		log.Fatalf("Error loading config for breakglass controller: %v", err)
	}

	if debug {
		log.Infof("%#v", config)
	}

	auth := api.NewAuth(log, config)
	server := api.NewServer(log.Desugar(), config, debug, auth)

	reviewDB, err := accessreview.NewAccessReviewDB(log, config)
	if err != nil {
		log.Fatalf("Error creating access review database manager: %v", err)
	}

	crdManager, err := accessreview.NewCRDManager()
	if err != nil {
		log.Fatalf("Error creating access review CRD manager: %v", err)
		return
	}

	ars, err := crdManager.GetClusterUserReviews("kind", "unknown")
	if err != nil {
		log.Fatalf("Error getting reviews from access review CRD manager: %v", err)
		return
	}

	ar, err := crdManager.GetClusterAccessReviewsByID(2)
	if err != nil {
		log.Fatalf("Error getting reviews from access review with id 2 from CRD manager: %v", err)
		return
	}
	fmt.Println("Ar with ID 2 :=", ar[0].Spec)

	for id, ar := range ars {
		fmt.Println("Current ar", id, " SPEC:=", ar.Spec)
	}

	err = server.RegisterAll([]api.APIController{
		breakglass.NewBreakglassController(log, config, auth.Middleware()),
		accessreview.NewClusterAccessReviewController(log, config, &reviewDB, auth.Middleware()),
		webhook.NewWebhookController(log, config, &reviewDB),
	})
	if err != nil {
		log.Fatalf("Error registering breakglass controllers: %v", err)
	}

	server.Listen()
}

func setupLogger(debug bool) *zap.SugaredLogger {
	var zlog *zap.Logger
	var err error
	if debug {
		zlog, err = zap.NewDevelopment()
	} else {
		zlog, err = zap.NewProduction()
	}
	if err != nil {
		stdlog.Fatalf("failed to set up logger: %v", err)
	}
	return zlog.Sugar()
}
