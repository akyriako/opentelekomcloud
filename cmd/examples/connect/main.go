package main

import (
	"fmt"
	"github.com/akyriako/opentelekomcloud/common"
	"os"
)

func main() {
	cloud := os.Getenv("OS_CLOUD")

	client, err := common.NewOpenTelekomCloudClient(cloud)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(client.ProjectClient.ProjectID, client.ProjectClient.RegionID)
}
