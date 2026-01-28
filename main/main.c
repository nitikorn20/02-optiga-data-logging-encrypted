/********************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2024-2025 TESA
 * All rights reserved.</center></h2>
 *
 * This source code and any compilation or derivative thereof is the
 * proprietary information of TESA and is confidential in nature.
 *
 ********************************************************************************
 * Project : OPTIGA Secure Data Logging Tutorial Series
 ********************************************************************************
 * Module  : Part 2 - Encrypted Data Logging (Key in OPTIGA)
 * Purpose : Demonstrate encrypt-before-storage using OPTIGA RNG + OPTIGA key.
 * Design  : See README.md for explanation
 ********************************************************************************
 * @file    main.c
 * @brief   Encrypted data logging demo for ESP32 (ESP-IDF)
 * @author  TESA Workshop Team
 * @date    January 10, 2026
 * @version 2.0.0
 *
 * @note    OPTIGA Trust M generates and stores the AES key (OID 0xE200).
 *          Encryption happens inside OPTIGA (AES-CBC).
 ********************************************************************************
 * Original Copyright Notice:
 * (c) 2010-2022, Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: CC0-1.0
 *******************************************************************************/

/* -------------------------------------------------------------------- */
/* Includes                                                             */
/* -------------------------------------------------------------------- */
#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "driver/uart.h"
#include "wear_levelling.h"
#include "sdmmc_cmd.h"
#include "driver/sdmmc_host.h"

#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/common/optiga_lib_common.h"

// --------------------
// Config
// --------------------
// 0 = internal SPI flash (FATFS + wear levelling)
// 1 = SD card via SDMMC (FATFS)
#ifndef LOG_STORAGE_SDMMC
#define LOG_STORAGE_SDMMC 0
#endif

#define LOG_SDMMC_BUS_WIDTH 1

#if LOG_STORAGE_SDMMC
#define LOG_MOUNT_POINT   "/sdcard"
#else
#define LOG_MOUNT_POINT   "/spiflash"
#endif

#define LOG_FILE_PATH     LOG_MOUNT_POINT "/enc_log.bin"
#define LOG_UART_NUM      UART_NUM_0
#define LOG_UART_BAUD     115200

#define AES_IV_BYTES      16
#define PLAINTEXT_MAX     64

// 1 = generate a fresh key in OPTIGA on every boot (overwrites slot)
// 0 = use existing key in OPTIGA key slot (0xE200)
#ifndef GENERATE_KEY_ON_BOOT
#define GENERATE_KEY_ON_BOOT 0
#endif

// --------------------
// Globals
// --------------------
static const char *TAG = "ENC_LOG";
static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;
static uint32_t s_log_seq = 0;
#if LOG_STORAGE_SDMMC
static sdmmc_card_t *s_sd_card = NULL;
#endif

static optiga_crypt_t *s_crypt = NULL;
static optiga_util_t *s_util = NULL;
static volatile optiga_lib_status_t s_optiga_status;

// --------------------
// OPTIGA Helpers
// --------------------
void pal_os_timer_delay_in_milliseconds(uint16_t milliseconds);

static void optiga_callback(void *context, optiga_lib_status_t return_status)
{
    (void)context;
    s_optiga_status = return_status;
}

static bool optiga_wait(void)
{
    while (s_optiga_status == OPTIGA_LIB_BUSY) {
        pal_os_timer_delay_in_milliseconds(5);
    }
    return (s_optiga_status == OPTIGA_LIB_SUCCESS);
}

static bool optiga_rng_fill(uint8_t *out, uint16_t len)
{
    s_optiga_status = OPTIGA_LIB_BUSY;
    if (optiga_crypt_random(s_crypt, OPTIGA_RNG_TYPE_TRNG, out, len) != OPTIGA_LIB_SUCCESS) {
        return false;
    }
    return optiga_wait();
}

static bool optiga_crypto_init(void)
{
    s_crypt = optiga_crypt_create(0, optiga_callback, NULL);
    if (s_crypt == NULL) {
        ESP_LOGE(TAG, "optiga_crypt_create failed");
        return false;
    }

    s_util = optiga_util_create(0, optiga_callback, NULL);
    if (s_util == NULL) {
        ESP_LOGE(TAG, "optiga_util_create failed");
        return false;
    }

    return true;
}

static bool optiga_key_ready(void)
{
    uint8_t metadata[64];
    uint16_t metadata_len = sizeof(metadata);
    const uint16_t oid = 0xE200;

    s_optiga_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t ret = optiga_util_read_metadata(
        s_util,
        oid,
        metadata,
        &metadata_len);
    if (ret != OPTIGA_LIB_SUCCESS) {
        return false;
    }
    if (!optiga_wait()) {
        return false;
    }
    if (metadata_len == 0) {
        return false;
    }

    ESP_LOGI(TAG, "OPTIGA key metadata length: %u", (unsigned)metadata_len);
    return true;
}

static bool optiga_write_e200_metadata(void)
{
    static const uint8_t e200_metadata[] = {0x20, 0x06, 0xD0, 0x01,
                                            0x00, 0xD3, 0x01, 0x00};
    const uint16_t oid = 0xE200;

    // Metadata config enables AES key usage in slot 0xE200
    ESP_LOGI(TAG, "Writing metadata for OPTIGA key slot 0xE200");
    s_optiga_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t ret = optiga_util_write_metadata(
        s_util,
        oid,
        e200_metadata,
        sizeof(e200_metadata));
    if (ret != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "optiga_util_write_metadata start failed: 0x%04X", ret);
        return false;
    }
    if (!optiga_wait()) {
        ESP_LOGE(TAG, "optiga_util_write_metadata failed");
        return false;
    }
    return true;
}

static bool optiga_generate_key_if_enabled(void)
{
    if (GENERATE_KEY_ON_BOOT) {
        ESP_LOGW(TAG, "GENERATE_KEY_ON_BOOT=1 (will overwrite key)");
        if (!optiga_write_e200_metadata()) {
            return false;
        }
    } else {
        if (optiga_key_ready()) {
            ESP_LOGI(TAG, "Using existing OPTIGA key (OID 0xE200)");
            return true;
        }

        ESP_LOGI(TAG, "OPTIGA key not ready. Initializing...");
        if (!optiga_write_e200_metadata()) {
            return false;
        }
    }

    // Generate and store the AES-128 key inside OPTIGA
    ESP_LOGI(TAG, "Generating AES-128 key in OPTIGA (OID 0xE200)...");
    s_optiga_status = OPTIGA_LIB_BUSY;
    optiga_key_id_t key_id = OPTIGA_KEY_ID_SECRET_BASED;
    optiga_lib_status_t ret = optiga_crypt_symmetric_generate_key(
        s_crypt,
        OPTIGA_SYMMETRIC_AES_128,
        (uint8_t)OPTIGA_KEY_USAGE_ENCRYPTION,
        FALSE,
        &key_id);
    if (ret != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "optiga_crypt_symmetric_generate_key start failed: 0x%04X", ret);
        return false;
    }
    if (!optiga_wait()) {
        ESP_LOGE(TAG, "optiga_crypt_symmetric_generate_key failed");
        return false;
    }
    ESP_LOGI(TAG, "AES key generated in OPTIGA");
    return true;
}

// --------------------
// Storage Helpers
// --------------------
static void print_usage(void)
{
    ESP_LOGI(TAG, "Commands:");
    ESP_LOGI(TAG, "  a - append encrypted record");
    ESP_LOGI(TAG, "  c - clear log file");
    ESP_LOGI(TAG, "  p - print raw file (hex)");
}

static void print_log_file_hex(void)
{
    FILE *f = fopen(LOG_FILE_PATH, "rb");
    if (!f) {
        ESP_LOGI(TAG, "no existing log file found.");
        return;
    }

    ESP_LOGI(TAG, "raw file content (hex):");
    uint8_t buf[32];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, buf, n, ESP_LOG_INFO);
    }
    fclose(f);
}

static bool encrypt_record(const uint8_t *plaintext, size_t pt_len,
                           uint8_t *record, size_t record_len)
{
    if (record_len < (AES_IV_BYTES + PLAINTEXT_MAX)) {
        return false;
    }

    uint8_t iv[AES_IV_BYTES];
    uint8_t ciphertext[PLAINTEXT_MAX];

    // Generate random IV using OPTIGA TRNG (one per record)
    if (!optiga_rng_fill(iv, sizeof(iv))) {
        ESP_LOGE(TAG, "IV generation failed");
        return false;
    }

    uint8_t pt_buf[PLAINTEXT_MAX];
    memset(pt_buf, 0, sizeof(pt_buf));
    memcpy(pt_buf, plaintext, pt_len);

    uint32_t cipher_len = sizeof(ciphertext);
    s_optiga_status = OPTIGA_LIB_BUSY;
    // OPTIGA performs AES-CBC using the key in slot 0xE200
    optiga_lib_status_t ret = optiga_crypt_symmetric_encrypt(
        s_crypt,
        OPTIGA_SYMMETRIC_CBC,
        OPTIGA_KEY_ID_SECRET_BASED,
        pt_buf,
        sizeof(pt_buf),
        iv,
        sizeof(iv),
        NULL,
        0,
        ciphertext,
        &cipher_len);
    if (ret != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "optiga_crypt_symmetric_encrypt start failed: 0x%04X", ret);
        return false;
    }
    if (!optiga_wait()) {
        ESP_LOGE(TAG, "optiga_crypt_symmetric_encrypt failed");
        return false;
    }
    if (cipher_len != sizeof(ciphertext)) {
        ESP_LOGE(TAG, "unexpected ciphertext length: %lu", (unsigned long)cipher_len);
        return false;
    }

    // Record format: IV (16B) + Ciphertext (64B) = 80B
    memcpy(record, iv, sizeof(iv));
    memcpy(record + sizeof(iv), ciphertext, sizeof(ciphertext));
    return true;
}

static void append_encrypted_record(void)
{
    char msg[PLAINTEXT_MAX];
    int64_t uptime_ms = esp_timer_get_time() / 1000;
    s_log_seq++;
    int written = snprintf(msg, sizeof(msg),
                           "{\"seq\":%lu,\"uptime_ms\":%lld}",
                           (unsigned long)s_log_seq,
                           (long long)uptime_ms);
    if (written < 0) {
        ESP_LOGE(TAG, "snprintf failed");
        return;
    }

    // Record format: IV (16B) + Ciphertext (64B) = 80B
    uint8_t record[AES_IV_BYTES + PLAINTEXT_MAX];
    if (!encrypt_record((const uint8_t *)msg, (size_t)written, record, sizeof(record))) {
        ESP_LOGE(TAG, "encrypt_record failed");
        return;
    }

    FILE *f = fopen(LOG_FILE_PATH, "ab");
    if (!f) {
        ESP_LOGE(TAG, "failed to open log file for append");
        return;
    }

    fwrite(record, 1, sizeof(record), f);
    fclose(f);

    ESP_LOGI(TAG, "encrypted: %s", msg);
}

static void clear_log_file(void)
{
    FILE *f = fopen(LOG_FILE_PATH, "wb");
    if (!f) {
        ESP_LOGE(TAG, "failed to open log file for clearing.");
        return;
    }
    fclose(f);
    ESP_LOGI(TAG, "log cleared.");
}

static esp_err_t mount_storage(void)
{
#if LOG_STORAGE_SDMMC
    const esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = true,
        .max_files = 4,
        .allocation_unit_size = 16 * 1024,
    };

    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();
    slot_config.width = LOG_SDMMC_BUS_WIDTH;
    slot_config.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

    esp_err_t err = esp_vfs_fat_sdmmc_mount(
        LOG_MOUNT_POINT, &host, &slot_config, &mount_config, &s_sd_card);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount SD card (err=0x%x)", err);
    }
    return err;
#else
    const esp_vfs_fat_mount_config_t mount_config = {
        .format_if_mount_failed = true,
        .max_files = 4,
        .allocation_unit_size = 4096,
    };

    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(
        LOG_MOUNT_POINT, "storage", &mount_config, &s_wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (err=0x%x)", err);
    }
    return err;
#endif
}

static void setup_uart(void)
{
    const uart_config_t uart_config = {
        .baud_rate = LOG_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    uart_driver_install(LOG_UART_NUM, 1024, 0, 0, NULL, 0);
    uart_param_config(LOG_UART_NUM, &uart_config);
    uart_set_pin(LOG_UART_NUM, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
}

static void command_loop(void)
{
    uint8_t ch;
    while (true) {
        int len = uart_read_bytes(LOG_UART_NUM, &ch, 1, 100 / portTICK_PERIOD_MS);
        if (len <= 0) {
            continue;
        }

        switch (ch) {
        case 'a':
        case 'A':
        case '1':
            append_encrypted_record();
            break;
        case 'c':
        case 'C':
        case '2':
            clear_log_file();
            break;
        case 'p':
        case 'P':
            print_log_file_hex();
            break;
        case '\r':
        case '\n':
            break;
        default:
            ESP_LOGW(TAG, "unknown command: %c", ch);
            print_usage();
            break;
        }

    }
}

void app_main(void)
{
    setup_uart();
    ESP_LOGI(TAG, "Encrypted data logging demo (ESP-IDF)");

    if (mount_storage() != ESP_OK) {
        ESP_LOGE(TAG, "mount failed. Check partition table.");
        return;
    }

    // OPTIGA init is required before RNG/crypto usage
    extern void optiga_trust_init(void);
    optiga_trust_init();

    if (!optiga_crypto_init()) {
        ESP_LOGE(TAG, "optiga init failed");
        return;
    }
    if (!optiga_generate_key_if_enabled()) {
        ESP_LOGE(TAG, "optiga key init failed");
        return;
    }

    print_log_file_hex();
    print_usage();
    command_loop();
}
