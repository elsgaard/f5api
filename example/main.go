package main

import (
	"fmt"
	"time"

	"github.com/elsgaard/f5api"
)

func main() {
	f5 := f5api.Model{
		User:       "f5-user",
		Pass:       "f5-pass",
		Host:       "f5-host.com",
		Port:       "443",
		MaxRetries: 3,
		RetryDelay: 500 * time.Millisecond,
	}

	f5.StartTokenRefresher()
	defer f5.StopTokenRefresher()

	stats, err := f5.GetPoolStats()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Got %d pools\n", len(stats.Entries))

	status, err := f5.GetSyncStatus()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Sync status: %v\n", status)

	//	status, err := f5.GetSyncStatus(token)
	//	if err != nil {
	//		log.Fatalf("Sync error: %v", err)
	//	}
	//	fmt.Printf("Sync status: %v\n", status)
}
