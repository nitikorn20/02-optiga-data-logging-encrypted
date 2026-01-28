idf_component_register(
  SRCS  "main.c"
  PRIV_REQUIRES spi_flash fatfs vfs wear_levelling driver esp_timer esp_system sdmmc
                 optiga esp_driver_i2c esp_driver_gpio
  INCLUDE_DIRS "."
)
