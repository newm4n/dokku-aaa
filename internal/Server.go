package internal

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hyperjumptech/jiffy"
	"github.com/newm4n/dokku-aaa/configuration"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

func configureLogging() {
	lLevel := configuration.Get("server.log.level")
	fmt.Println("Setting log level to ", lLevel)
	switch strings.ToUpper(lLevel) {
	default:
		fmt.Println("Unknown level [", lLevel, "]. Log level set to ERROR")
		log.SetLevel(log.ErrorLevel)
	case "TRACE":
		log.SetLevel(log.TraceLevel)
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	case "WARN":
		log.SetLevel(log.WarnLevel)
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
	case "FATAL":
		log.SetLevel(log.FatalLevel)
	}
}

// Start this server
func Start() {
	configureLogging()
	log.Infof("Starting Server")
	startTime := time.Now()
	router := mux.NewRouter()

	InitRouter(router)

	var wait time.Duration

	graceShut, err := jiffy.DurationOf(configuration.Get("server.timeout.graceshut"))
	if err != nil {
		panic(err)
	}
	WriteTimeout, err := jiffy.DurationOf(configuration.Get("server.timeout.write"))
	if err != nil {
		panic(err)
	}
	ReadTimeout, err := jiffy.DurationOf(configuration.Get("server.timeout.read"))
	if err != nil {
		panic(err)
	}
	IdleTimeout, err := jiffy.DurationOf(configuration.Get("server.timeout.idle"))
	if err != nil {
		panic(err)
	}

	wait = graceShut

	address := fmt.Sprintf("%s:%s", configuration.Get("server.host"), configuration.Get("server.port"))
	log.Info("Server binding to ", address)

	srv := &http.Server{
		Addr: address,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: WriteTimeout,
		ReadTimeout:  ReadTimeout,
		IdleTimeout:  IdleTimeout,
		// Handler:      Router, // Pass our instance of gorilla/mux in.
		Handler: router,
	}
	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	dur := time.Now().Sub(startTime)
	durDesc := jiffy.DescribeDuration(dur, jiffy.NewWant())
	log.Infof("Shutting down. This Hansip been protecting the world for %s", durDesc)
	os.Exit(0)
}
