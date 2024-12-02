# MISP Feed

MISP provides a function called feed that enables you to fetch MISP events from a server. It can be used to fetch the **vmray-feed**.

## Create a New Local Feed

To import events created by the **vmray-feed**, create a new feed, as follows:

Go to `Sync Action -> List Feeds` and click on `Add Feed` on the left hand side and fill in the form:

* **Enable**: True
* **Name**: VMRay-Feed
* **Provider**: VMRay
* **Input Source**: Local
* **Remove input after ingestion**: True
* **URL**: /var/www/MISP/app/tmp/vmray-misp-feed (if you changed `feed_path` in `config.toml`, point the path to the new location instead)
* **Source Format**: MISP Feed

![Screenshot](./assets/create-feed.png)

### Filtering

By filtering for VMRay tags, you can specify both allowed and blocked tags, allowing for more precise control over which items are imported. For a full list of supported VMRay tags, visit **Event Actions / List Taxonomies / vmray**. By enabling all **vmray** taxonomies, you can gain access to a wider selection of tags used by VMRay.

If you wish to import only samples labeled with a verdict of 'malicious', please follow the steps outlined in the example below:

1. Navigate to **Sync Action / Feeds** and select **Edit VMRay Feed**.
2. Click on **Modify** under **Filter Rules** to open the **Set Pull Rules** window.
3. In the **Show freetext input** section, enter the tag:  
   `vmray:verdict="malicious"`. Alternatively, if the **vmray taxonomies** are enabled, you can use the pre-configured tags.
4. Click the left arrow to add the tag to the allowed tags list.

Additionally, ensure that you set `use_vmray_tags = true` in the `config.toml` file located in the **vmray-misp-feed** folder.
