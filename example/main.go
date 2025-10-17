package main

import (
	"fmt"
	"log"
	"time"

	"github.com/elsgaard/f5api"
)

func main() {
	f5 := f5api.Model{
		User:       "f5-user",
		Pass:       "f5-pass",
		Host:       "lb.host.com",
		Port:       "443",
		MaxRetries: 3,
		RetryDelay: 500 * time.Millisecond,
	}

	token, err := f5.Login()
	if err != nil {
		log.Fatalf("Auth failed: %v", err)
	}
	defer f5.Logout(token)

	stats, err := f5.GetPoolStats(token)
	if err != nil {
		log.Fatalf("Stats error: %v", err)
	}
	fmt.Printf("Got %d pools\n", len(stats.Entries))

	status, err := f5.GetSyncStatus(token)
	if err != nil {
		log.Fatalf("Sync error: %v", err)
	}
	fmt.Printf("Sync status: %v\n", status)
}
