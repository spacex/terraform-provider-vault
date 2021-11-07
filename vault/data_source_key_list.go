package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/vault/api"
)

func genericKeyListDataSource() *schema.Resource {
	return &schema.Resource{
		Read: genericKeyListDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Full path from which a list of secrets will be read.",
			},

			"secret_list": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Secret list read from Vault.",
				Sensitive:   false,
			},

			"secret_list_json": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded secret list read from Vault.",
				Sensitive:   false,
			},
		},
	}
}

func genericKeyListDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error reading KV version: %s", err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "metadata")
	}

	keyList, err := client.Logical().List(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	if keyList == nil {
		return fmt.Errorf("no secrets found at %q", path)
	}

	d.SetId(path)

	// Ignoring error because this value came from JSON in the
	// first place so no reason why it should fail to re-encode.
	jsonDataBytes, _ := json.Marshal(keyList.Data)
	d.Set("key_list_json", string(jsonDataBytes))

	dataList := make([]string, 0)
	for k := range keyList.Data {
		dataList = append(dataList, k)
	}

	log.Printf("[DEBUG] %s", dataList)
	d.Set("key_list", dataList)

	return nil
}
