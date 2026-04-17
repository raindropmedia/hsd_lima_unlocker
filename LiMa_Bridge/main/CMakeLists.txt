idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_netif esp_event nvs_flash esp_http_client esp-tls esp_https_ota app_update wpa_supplicant
)

# APP_VERSION als C-Präprozessor-Define aus PROJECT_VER (CMakeLists.txt root)
target_compile_definitions(${COMPONENT_LIB} PRIVATE APP_VERSION="${PROJECT_VER}")

# HSD-Logo: vorgeneriertes C-Array direkt einbinden (via LVGLImage.py, ARGB8888)
lvgl_port_add_images(${COMPONENT_LIB} "images/")
