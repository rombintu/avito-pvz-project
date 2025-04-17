package server

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rombintu/avito-pvz-project/internal/metrics"
)

func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()

		c.Next()

		duration := time.Since(start).Seconds()
		status := c.Writer.Status()

		metrics.RequestsTotal.With(prometheus.Labels{
			"method": c.Request.Method,
			"path":   path,
			"status": http.StatusText(status),
		}).Inc()

		metrics.ResponseTime.With(prometheus.Labels{
			"method": c.Request.Method,
			"path":   path,
		}).Observe(duration)
	}
}
