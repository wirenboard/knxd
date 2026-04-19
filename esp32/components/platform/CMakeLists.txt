# Component: platform abstraction for ESP32
# Provides config.h and platform-specific stubs

idf_component_register(
    SRCS "platform_esp32.cpp"
    INCLUDE_DIRS "."
    REQUIRES driver esp_wifi esp_netif nvs_flash
)
