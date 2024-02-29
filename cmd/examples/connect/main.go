package main

import (
	"fmt"
	"github.com/akyriako/opentelekomcloud/auth"
	"os"
)

func main() {
	cloud := os.Getenv("OS_CLOUD")

	client, err := auth.NewOpenTelekomCloudClient(cloud)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(client.ProjectClient.ProjectID, client.ProjectClient.RegionID)
}
