idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES "server_cert.pem"
    REQUIRES esp_wifi esp_netif esp_event nvs_flash esp_http_client esp-tls esp_https_ota app_update
)
