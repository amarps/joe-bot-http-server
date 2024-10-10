package joehttp

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

const ErrMissingPort = "missing port in address"

func WhitelistIp(h http.HandlerFunc, s *server) http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		var userIp string
		userIp, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			if !strings.Contains(err.Error(), ErrMissingPort) {
				s.logger.Error("Error parsing RemoteAddr", zap.String("RemoteAddr", r.RemoteAddr))

				newErr := fmt.Errorf("%s is not a valid IP address", r.RemoteAddr)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(newErr.Error()))
				return
			}

			userIp = strings.Split(r.RemoteAddr, ":")[0]
		}

		found := false
		for _, wIp := range s.whitelistIps {
			if CompareIp(wIp, userIp) {
				found = true
				break
			}
		}

		if !found {
			newErr := fmt.Errorf("%s is not registered in the whitelist IP", userIp)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(newErr.Error()))
			return
		}

		h.ServeHTTP(w, r.WithContext(r.Context()))
	}

	return http.HandlerFunc(fn)
}

// compare IP or CIDR network
func CompareIp(comparable, ip string) bool {
	var clientIp = net.ParseIP(ip)
	if clientIp == nil {
		return false
	}

	var comparableIp = net.ParseIP(comparable)
	if comparableIp != nil {
		return comparableIp.Equal(clientIp)
	}

	_, comparableNetwork, err := net.ParseCIDR(comparable)
	if err == nil {
		return comparableNetwork.Contains(clientIp)
	}

	return false
}
