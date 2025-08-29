# rdpsign

This module implements RDP signing based on the implementation here: 
[https://gitee.com/cyberkylin/rdpsign](https://gitee.com/cyberkylin/rdpsign)

There were some minor changes to error handling and the signing process
was changed into a module, but all the major functionality is unchanged.

## Usage

```go
package main

import (
    "fmt"
    "os"

    "github.com/andrewheberle/rdpsign"
)

func main() {
    signer, err := rdpsign.NewSigner("/path/to/cert", "/path/to/key")
    if err != nil {
        fmt.Printf("Error: %s", err)
        os.Exit(1)
    }

    rdpContent := "contents of\nyour rdp\nfile are here\n"

    signedRdpContent, err := signer.SignRdp(rdpContent)
    if err != nil {
        fmt.Printf("Error: %s", err)
        os.Exit(1)
    }

    fmt.Println(string(signedRdpContent))
}
```

## Credits and Copyright

The major functionality for this module came from [https://gitee.com/cyberkylin/rdpsign](https://gitee.com/cyberkylin/rdpsign)
and all relevant copyrights are still in place.
