# f5api

A simple and robust Go client for interacting with the F5 BIG-IP REST API, including authentication, pool statistics, and sync status retrieval.

## ✨ Features

- 🔐 Authenticates via F5's `/mgmt/shared/authn/login` endpoint
- 📊 Fetches pool statistics from `/mgmt/tm/ltm/pool/stats`
- 🔄 Retrieves device sync status from `/mgmt/tm/cm/sync-status`
- 🔁 Built-in retry logic with exponential backoff and jitter
- ❌ Logs out and invalidates session token
- ✅ No external dependencies (fully native Go)

---

## 📦 Installation

```bash
go get github.com/elsgaard/f5api
````

## 🛠 Usage

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/elsgaard/f5api"
)

func main() {
    f5 := f5api.Model{
        User:       "admin",
        Pass:       "yourpassword",
        Host:       "f5.example.com",
        Port:       "443",
        MaxRetries: 3,
        RetryDelay: 500 * time.Millisecond,
    }

    token, err := f5.Authenticate()
    if err != nil {
        log.Fatalf("Authentication failed: %v", err)
    }
    defer f5.Logout(token)

    stats, err := f5.GetPoolStats(token)
    if err != nil {
        log.Fatalf("Failed to get pool stats: %v", err)
    }
    fmt.Printf("Found %d pools\n", len(stats.Entries))

    sync, err := f5.GetSyncStatus(token)
    if err != nil {
        log.Fatalf("Failed to get sync status: %v", err)
    }

    if sync == 1 {
        fmt.Println("Device is in sync")
    } else {
        fmt.Println("Device is NOT in sync")
    }
}
```

---

## ⚠️ Security Notice

By default, TLS certificate verification is disabled in this package (`InsecureSkipVerify: true`). This is convenient for testing but **should not be used in production**.

To make this secure:

* Replace `InsecureSkipVerify` with proper root CA validation.
* Consider passing a custom `*http.Client` or TLS config.

---

## 🧪 Development

This package is written in idiomatic Go and can be extended with:

* Support for more F5 API endpoints

---

## 📄 License

[MIT](LICENSE)

---

## 🙌 Contributions

Feel free to open issues or PRs. Bug fixes, documentation, and new features are welcome!

```
