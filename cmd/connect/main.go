package main

import (
	"fmt"
	"github.com/akyriako/opentelekomcloud/common"
	"os"
)

func main() {
	client, err := common.NewOpenTelekomCloudClient("eu-de")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(client)
}
