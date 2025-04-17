package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Technical metrics
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status"})

	ResponseTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_response_time_seconds",
		Help:    "Duration of HTTP requests",
		Buckets: []float64{0.1, 0.5, 1, 2, 5},
	}, []string{"method", "path"})

	// Business metrics
	PVZCreated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pvz_created_total",
		Help: "Total number of PVZ created",
	})

	ReceptionsCreated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "receptions_created_total",
		Help: "Total number of order receptions created",
	})

	ProductsAdded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "products_added_total",
		Help: "Total number of products added",
	})
)
