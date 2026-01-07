/**
 * QEMU WLAN access point emulation
 *
 * Copyright (c) 2008 Clemens Kolbitsch
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Modifications:
 *  2008-February-24  Clemens Kolbitsch :
 *                                  New implementation based on ne2000.c
 *  18/1/22 Martin Johnson : Modified for esp32 wifi emulation
 */

#include "qemu/osdep.h"
#include "net/net.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qapi/error.h"

#include "crypto/cipher.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf.h"
#include "crypto/random.h"
#include "hw/misc/esp32_wifi.h"
#include "esp32_wlan.h"
#include "esp32_wlan_packet.h"

// 50ms between beacons
#define BEACON_TIME 50000000
#define INTER_FRAME_TIME 5000000
#define DEBUG_DUMPFRAMES 0

// channel 12, 13 and 14 aren't scanned with probe requests, but by listening to beacons
// likely because those channels aren't freely licensed in all countries
access_point_info access_points[]={
    {"EVCS-QEMU",4,-40,{0x10,0x01,0x00,0xc4,0x0a,0x51}, 1, "H5xLmTU5#"},
    {"Open Wifi",4,-40,{0x10,0x01,0x00,0xc4,0x0a,0x50}, 0, NULL},
    {"Zeus WPI",12,-25,{0x10,0x01,0x00,0xc4,0x0a,0x56}, 0, NULL}
};

int nb_aps=sizeof(access_points)/sizeof(access_point_info);

static bool esp32_wifi_debug_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        enabled = getenv("ESP32_WIFI_AP_DEBUG") != NULL;
    }
    return enabled;
}

static bool esp32_wifi_debug_beacons_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        enabled = getenv("ESP32_WIFI_AP_DEBUG_BEACONS") != NULL;
    }
    return enabled;
}

/* WPA2-PSK (RSN/CCMP) minimal 4-way handshake (enough for ESP-IDF station mode). */
#define WPA2_EAPOL_ETHERTYPE 0x888e
#define WPA2_EAPOL_VERSION 2
#define WPA2_EAPOL_TYPE_KEY 3
#define WPA2_EAPOL_KEY_DESC_RSN 2

/* Key Information bits (host-endian; written big-endian). */
#define WPA2_KEY_INFO_VERSION_AES 0x0002
#define WPA2_KEY_INFO_KEY_TYPE_PAIRWISE 0x0008
#define WPA2_KEY_INFO_INSTALL 0x0040
#define WPA2_KEY_INFO_ACK 0x0080
#define WPA2_KEY_INFO_MIC 0x0100
#define WPA2_KEY_INFO_SECURE 0x0200
#define WPA2_KEY_INFO_ENCR_KEY_DATA 0x1000

#define WPA2_PMK_LEN 32
#define WPA2_PTK_LEN 64
#define WPA2_KCK_LEN 16
#define WPA2_KEK_LEN 16
#define WPA2_GTK_LEN 16
#define WPA2_NONCE_LEN 32
#define WPA2_TK_OFF (WPA2_KCK_LEN + WPA2_KEK_LEN)

#define CCMP_HDR_LEN 8
#define CCMP_MIC_LEN 8

#define WPA2_EAPOL_HDR_LEN 4
#define WPA2_EAPOL_KEY_FIXED_LEN 95 /* descriptor_type + fixed fields, excluding key_data */
#define WPA2_EAPOL_KEY_MIC_OFF (WPA2_EAPOL_HDR_LEN + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8)
#define WPA2_EAPOL_KEY_DATA_LEN_OFF (WPA2_EAPOL_KEY_MIC_OFF + 16)

static void esp32_ccmp_pn_to_bytes(uint64_t pn, uint8_t pn_out[6])
{
    pn_out[0] = (uint8_t)(pn & 0xffu);
    pn_out[1] = (uint8_t)((pn >> 8) & 0xffu);
    pn_out[2] = (uint8_t)((pn >> 16) & 0xffu);
    pn_out[3] = (uint8_t)((pn >> 24) & 0xffu);
    pn_out[4] = (uint8_t)((pn >> 32) & 0xffu);
    pn_out[5] = (uint8_t)((pn >> 40) & 0xffu);
}

static void esp32_ccmp_build_header(uint8_t hdr[CCMP_HDR_LEN], const uint8_t pn[6], uint8_t keyid)
{
    hdr[0] = pn[0];
    hdr[1] = pn[1];
    hdr[2] = 0x00;
    hdr[3] = (uint8_t)((keyid & 0x3u) << 6) | 0x20; /* ExtIV */
    hdr[4] = pn[2];
    hdr[5] = pn[3];
    hdr[6] = pn[4];
    hdr[7] = pn[5];
}

static uint16_t esp32_ld_be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static void esp32_st_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static uint64_t esp32_ld_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void esp32_st_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xffu);
        v >>= 8;
    }
}

static int esp32_find_ap_by_mac(const uint8_t mac[6])
{
    for (int i = 0; i < nb_aps; i++) {
        if (memcmp(access_points[i].mac_address, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

static void esp32_wpa2_reset(Esp32WifiState *s)
{
    s->wpa2_enabled = 0;
    s->wpa2_state = 0;
    s->wpa2_handshake_done = 0;
    memset(s->wpa2_sta_mac, 0, sizeof(s->wpa2_sta_mac));
    s->wpa2_ssid = NULL;
    s->wpa2_psk = NULL;
    s->wpa2_replay_counter = 0;
    memset(s->wpa2_anonce, 0, sizeof(s->wpa2_anonce));
    memset(s->wpa2_snonce, 0, sizeof(s->wpa2_snonce));
    memset(s->wpa2_pmk, 0, sizeof(s->wpa2_pmk));
    memset(s->wpa2_ptk, 0, sizeof(s->wpa2_ptk));
    memset(s->wpa2_gtk, 0, sizeof(s->wpa2_gtk));
    s->wpa2_group_keyid = 0;
    s->wpa2_tx_pn = 0;
    s->wpa2_tx_pn_group = 0;
}

static bool esp32_hmac_sha1(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t out[20])
{
    Error *err = NULL;
    g_autoptr(QCryptoHmac) hmac = qcrypto_hmac_new(QCRYPTO_HASH_ALGO_SHA1, key, key_len, &err);
    if (!hmac) {
        error_report_err(err);
        return false;
    }

    uint8_t *outp = out;
    size_t outlen = 20;
    if (qcrypto_hmac_bytes(hmac, (const char *)data, data_len, &outp, &outlen, &err) < 0) {
        error_report_err(err);
        return false;
    }
    if (outlen != 20) {
        error_report("esp32-wifi: unexpected HMAC-SHA1 length: %zu", outlen);
        return false;
    }
    return true;
}

static bool esp32_wpa2_prf_sha1(const uint8_t pmk[WPA2_PMK_LEN],
                                const uint8_t *data, size_t data_len,
                                uint8_t out[WPA2_PTK_LEN])
{
    static const char label[] = "Pairwise key expansion";
    uint8_t msg[sizeof(label) + 1 + 128 + 1];
    size_t pos = 0;

    memcpy(msg + pos, label, sizeof(label) - 1);
    pos += sizeof(label) - 1;
    msg[pos++] = 0x00;
    if (data_len > 128) {
        error_report("esp32-wifi: PRF input too large: %zu", data_len);
        return false;
    }
    memcpy(msg + pos, data, data_len);
    pos += data_len;

    for (uint8_t i = 0; i < (WPA2_PTK_LEN + 19) / 20; i++) {
        msg[pos] = i;
        uint8_t digest[20];
        if (!esp32_hmac_sha1(pmk, WPA2_PMK_LEN, msg, pos + 1, digest)) {
            return false;
        }
        size_t to_copy = WPA2_PTK_LEN - (size_t)i * 20;
        if (to_copy > 20) {
            to_copy = 20;
        }
        memcpy(out + (size_t)i * 20, digest, to_copy);
    }
    return true;
}

static bool esp32_wpa2_derive_pmk(const char *passphrase, const char *ssid, uint8_t pmk[WPA2_PMK_LEN])
{
    Error *err = NULL;

    if (!qcrypto_pbkdf2_supports(QCRYPTO_HASH_ALGO_SHA1)) {
        error_report("esp32-wifi: PBKDF2-SHA1 not supported by this QEMU build");
        return false;
    }

    const uint64_t iters = 4096;
    if (qcrypto_pbkdf2(QCRYPTO_HASH_ALGO_SHA1,
                       (const uint8_t *)passphrase, strlen(passphrase),
                       (const uint8_t *)ssid, strlen(ssid),
                       iters,
                       pmk, WPA2_PMK_LEN,
                       &err) < 0) {
        error_report_err(err);
        return false;
    }
    return true;
}

static bool esp32_aes_128_ecb(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    Error *err = NULL;
    g_autoptr(QCryptoCipher) cipher = qcrypto_cipher_new(QCRYPTO_CIPHER_ALGO_AES_128,
                                                         QCRYPTO_CIPHER_MODE_ECB,
                                                         key, 16, &err);
    if (!cipher) {
        error_report_err(err);
        return false;
    }
    if (qcrypto_cipher_encrypt(cipher, in, out, 16, &err) < 0) {
        error_report_err(err);
        return false;
    }
    return true;
}

/* RFC3394 AES key wrap */
static bool esp32_aes_key_wrap_128(const uint8_t kek[16],
                                  const uint8_t *plain, size_t plain_len,
                                  uint8_t *out, size_t *out_len)
{
    if (plain_len < 16 || (plain_len % 8) != 0) {
        error_report("esp32-wifi: invalid keywrap length: %zu", plain_len);
        return false;
    }
    const size_t n = plain_len / 8;
    if (*out_len < plain_len + 8) {
        error_report("esp32-wifi: keywrap output buffer too small");
        return false;
    }

    uint8_t a[8] = {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
    memcpy(out + 8, plain, plain_len);

    for (int j = 0; j <= 5; j++) {
        for (size_t i = 1; i <= n; i++) {
            uint8_t b[16];
            uint8_t in[16];

            memcpy(in, a, 8);
            memcpy(in + 8, out + 8 * i, 8);
            if (!esp32_aes_128_ecb(kek, in, b)) {
                return false;
            }

            uint64_t t = (uint64_t)(n * (size_t)j + i);
            memcpy(a, b, 8);
            for (int k = 0; k < 8; k++) {
                a[7 - k] ^= (uint8_t)(t & 0xffu);
                t >>= 8;
            }
            memcpy(out + 8 * i, b + 8, 8);
        }
    }

    memcpy(out, a, 8);
    *out_len = plain_len + 8;
    return true;
}

static void esp32_wpa2_compute_mic(const uint8_t kck[WPA2_KCK_LEN],
                                  const uint8_t *eapol, size_t eapol_len,
                                  uint8_t mic_out[16])
{
    uint8_t digest[20] = {0};
    if (!esp32_hmac_sha1(kck, WPA2_KCK_LEN, eapol, eapol_len, digest)) {
        memset(mic_out, 0, 16);
        return;
    }
    memcpy(mic_out, digest, 16);
}

static size_t esp32_wpa2_build_eapol_key(uint8_t *out, size_t out_cap,
                                        uint16_t key_info, uint64_t replay_counter,
                                        const uint8_t nonce[WPA2_NONCE_LEN],
                                        const uint8_t *key_data, uint16_t key_data_len,
                                        const uint8_t *kck /* optional */)
{
    const size_t total_len = WPA2_EAPOL_HDR_LEN + WPA2_EAPOL_KEY_FIXED_LEN + key_data_len;
    if (out_cap < total_len) {
        return 0;
    }

    /* EAPOL header */
    out[0] = WPA2_EAPOL_VERSION;
    out[1] = WPA2_EAPOL_TYPE_KEY;
    esp32_st_be16(&out[2], (uint16_t)(WPA2_EAPOL_KEY_FIXED_LEN + key_data_len));

    size_t p = WPA2_EAPOL_HDR_LEN;
    out[p++] = WPA2_EAPOL_KEY_DESC_RSN;

    esp32_st_be16(&out[p], key_info);
    p += 2;
    esp32_st_be16(&out[p], 16); /* key length: CCMP */
    p += 2;
    esp32_st_be64(&out[p], replay_counter);
    p += 8;
    memcpy(&out[p], nonce, WPA2_NONCE_LEN);
    p += WPA2_NONCE_LEN;

    memset(&out[p], 0, 16); /* key IV */
    p += 16;
    memset(&out[p], 0, 8); /* key RSC */
    p += 8;
    memset(&out[p], 0, 8); /* key ID */
    p += 8;

    /* MIC is computed over the whole EAPOL payload with this field zeroed. */
    const size_t mic_pos = p;
    memset(&out[p], 0, 16);
    p += 16;

    esp32_st_be16(&out[p], key_data_len);
    p += 2;
    if (key_data_len) {
        memcpy(&out[p], key_data, key_data_len);
        p += key_data_len;
    }

    if (p != total_len) {
        error_report("esp32-wifi: EAPOL build length mismatch: %zu != %zu", p, total_len);
        return 0;
    }

    if (kck && (key_info & WPA2_KEY_INFO_MIC)) {
        uint8_t mic[16];
        esp32_wpa2_compute_mic(kck, out, total_len, mic);
        memcpy(&out[mic_pos], mic, 16);
    }

    return total_len;
}

static void esp32_wpa2_send_eapol(Esp32WifiState *s, const uint8_t *eapol, size_t eapol_len, int sigstrength)
{
    uint8_t eth[14 + 256];
    if (eapol_len > 256) {
        error_report("esp32-wifi: EAPOL frame too large: %zu", eapol_len);
        return;
    }
    memcpy(eth + 0, s->wpa2_sta_mac, 6);
    memcpy(eth + 6, s->associated_ap_macaddr, 6);
    eth[12] = 0x88;
    eth[13] = 0x8e;
    memcpy(eth + 14, eapol, eapol_len);

    struct mac80211_frame *frame = Esp32_WLAN_create_data_packet(s, eth, (int)(14 + eapol_len));
    if (!frame) {
        return;
    }
    frame->frame_control.to_ds = 0;
    frame->frame_control.from_ds = 1;
    memcpy(frame->receiver_address, s->wpa2_sta_mac, 6);
    memcpy(frame->transmitter_address, s->associated_ap_macaddr, 6);
    memcpy(frame->address_3, s->associated_ap_macaddr, 6);
    frame->signal_strength = sigstrength;
    Esp32_WLAN_init_ap_frame(s, frame);
    Esp32_WLAN_insert_frame(s, frame);
}

static bool esp32_wpa2_start(Esp32WifiState *s, access_point_info *ap, const uint8_t sta_mac[6])
{
    if (!ap->wpa2_psk || !ap->psk || ap->psk[0] == '\0') {
        return false;
    }

    esp32_wpa2_reset(s);
    s->wpa2_enabled = 1;
    s->wpa2_state = 1; /* WAIT_M2 */
    s->wpa2_ssid = ap->ssid;
    s->wpa2_psk = ap->psk;
    memcpy(s->wpa2_sta_mac, sta_mac, 6);

    if (!esp32_wpa2_derive_pmk(s->wpa2_psk, s->wpa2_ssid, s->wpa2_pmk)) {
        esp32_wpa2_reset(s);
        return false;
    }

    Error *err = NULL;
    (void)qcrypto_random_init(&err);
    if (err) {
        error_report_err(err);
        esp32_wpa2_reset(s);
        return false;
    }
    if (qcrypto_random_bytes(s->wpa2_anonce, WPA2_NONCE_LEN, &err) < 0) {
        error_report_err(err);
        esp32_wpa2_reset(s);
        return false;
    }
    if (qcrypto_random_bytes(s->wpa2_gtk, WPA2_GTK_LEN, &err) < 0) {
        error_report_err(err);
        esp32_wpa2_reset(s);
        return false;
    }

    s->wpa2_replay_counter = 1;

    uint8_t msg1[WPA2_EAPOL_HDR_LEN + WPA2_EAPOL_KEY_FIXED_LEN];
    size_t msg1_len = esp32_wpa2_build_eapol_key(
        msg1,
        sizeof(msg1),
        (uint16_t)(WPA2_KEY_INFO_VERSION_AES | WPA2_KEY_INFO_KEY_TYPE_PAIRWISE | WPA2_KEY_INFO_ACK),
        s->wpa2_replay_counter,
        s->wpa2_anonce,
        NULL,
        0,
        NULL);

    if (msg1_len == 0) {
        esp32_wpa2_reset(s);
        return false;
    }

    if (esp32_wifi_debug_enabled()) {
        printf("QEMU: WPA2 start ssid='%s' sta=%02x:%02x:%02x:%02x:%02x:%02x replay=%" PRIu64 "\n",
               s->wpa2_ssid,
               sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5],
               s->wpa2_replay_counter);
    }

    esp32_wpa2_send_eapol(s, msg1, msg1_len, ap->sigstrength);
    return true;
}

static bool esp32_wpa2_handle_eapol(Esp32WifiState *s, access_point_info *ap,
                                   const uint8_t *eapol, size_t eapol_len)
{
    if (!s->wpa2_enabled || !s->wpa2_psk || !s->wpa2_ssid) {
        return false;
    }
    if (eapol_len < WPA2_EAPOL_HDR_LEN + WPA2_EAPOL_KEY_FIXED_LEN) {
        return false;
    }
    /* Accept legacy EAPOL v1 as some stations still use it for WPA2. */
    if (!((eapol[0] == 1) || (eapol[0] == WPA2_EAPOL_VERSION)) || eapol[1] != WPA2_EAPOL_TYPE_KEY) {
        return false;
    }
    const uint16_t body_len = esp32_ld_be16(&eapol[2]);
    if ((size_t)body_len + WPA2_EAPOL_HDR_LEN != eapol_len) {
        return false;
    }

    if (eapol[WPA2_EAPOL_HDR_LEN] != WPA2_EAPOL_KEY_DESC_RSN) {
        return false;
    }
    const uint16_t key_info = esp32_ld_be16(&eapol[WPA2_EAPOL_HDR_LEN + 1]);
    const uint64_t replay = esp32_ld_be64(&eapol[WPA2_EAPOL_HDR_LEN + 1 + 2 + 2]);
    const uint8_t *nonce = &eapol[WPA2_EAPOL_HDR_LEN + 1 + 2 + 2 + 8];

    const uint16_t key_data_len = esp32_ld_be16(&eapol[WPA2_EAPOL_KEY_DATA_LEN_OFF]);
    if (WPA2_EAPOL_HDR_LEN + WPA2_EAPOL_KEY_FIXED_LEN + (size_t)key_data_len != eapol_len) {
        return false;
    }

    if (esp32_wifi_debug_enabled()) {
        printf("QEMU: WPA2 EAPOL-Key rx state=%d key_info=0x%04x replay=%" PRIu64 " key_data_len=%u len=%zu\n",
               s->wpa2_state,
               key_info,
               replay,
               key_data_len,
               eapol_len);
    }

    if (s->wpa2_state == 1) {
        /* Expect message 2 */
        if ((key_info & (WPA2_KEY_INFO_MIC | WPA2_KEY_INFO_KEY_TYPE_PAIRWISE)) !=
            (WPA2_KEY_INFO_MIC | WPA2_KEY_INFO_KEY_TYPE_PAIRWISE)) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: WPA2 msg2 reject: key_info=0x%04x\n", key_info);
            }
            return false;
        }
        if (replay != s->wpa2_replay_counter) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: WPA2 msg2 reject: replay=%" PRIu64 " expected=%" PRIu64 "\n",
                       replay,
                       s->wpa2_replay_counter);
            }
            return false;
        }
        memcpy(s->wpa2_snonce, nonce, WPA2_NONCE_LEN);

        /* Derive PTK */
        uint8_t data[6 + 6 + WPA2_NONCE_LEN + WPA2_NONCE_LEN];
        const uint8_t *aa = s->associated_ap_macaddr;
        const uint8_t *spa = s->wpa2_sta_mac;
        const uint8_t *anonce = s->wpa2_anonce;
        const uint8_t *snonce = s->wpa2_snonce;

        if (memcmp(aa, spa, 6) < 0) {
            memcpy(data + 0, aa, 6);
            memcpy(data + 6, spa, 6);
        } else {
            memcpy(data + 0, spa, 6);
            memcpy(data + 6, aa, 6);
        }
        if (memcmp(anonce, snonce, WPA2_NONCE_LEN) < 0) {
            memcpy(data + 12, anonce, WPA2_NONCE_LEN);
            memcpy(data + 12 + WPA2_NONCE_LEN, snonce, WPA2_NONCE_LEN);
        } else {
            memcpy(data + 12, snonce, WPA2_NONCE_LEN);
            memcpy(data + 12 + WPA2_NONCE_LEN, anonce, WPA2_NONCE_LEN);
        }

        if (!esp32_wpa2_prf_sha1(s->wpa2_pmk, data, sizeof(data), s->wpa2_ptk)) {
            return false;
        }

        /* Verify MIC of message 2 */
        uint8_t tmp[256];
        if (eapol_len > sizeof(tmp)) {
            return false;
        }
        memcpy(tmp, eapol, eapol_len);
        memset(&tmp[WPA2_EAPOL_KEY_MIC_OFF], 0, 16);
        uint8_t mic[16];
        esp32_wpa2_compute_mic(s->wpa2_ptk, tmp, eapol_len, mic);
        if (memcmp(mic, &eapol[WPA2_EAPOL_KEY_MIC_OFF], 16) != 0) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: WPA2 msg2 reject: MIC mismatch\n");
            }
            return false;
        }

        /* Build GTK KDE and wrap with KEK */
        s->wpa2_group_keyid = 1;
        const uint8_t gtk_kde_plain[] = {
            0xdd, 0x16, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00,
            /* GTK (16) follows */
        };
        uint8_t plain[24];
        memcpy(plain, gtk_kde_plain, 8);
        memcpy(plain + 8, s->wpa2_gtk, WPA2_GTK_LEN);

        uint8_t wrapped[32];
        size_t wrapped_len = sizeof(wrapped);
        const uint8_t *kek = s->wpa2_ptk + WPA2_KCK_LEN;
        if (!esp32_aes_key_wrap_128(kek, plain, sizeof(plain), wrapped, &wrapped_len)) {
            return false;
        }

        s->wpa2_replay_counter++;

        uint8_t msg3[WPA2_EAPOL_HDR_LEN + WPA2_EAPOL_KEY_FIXED_LEN + 64];
        size_t msg3_len = esp32_wpa2_build_eapol_key(
            msg3,
            sizeof(msg3),
            (uint16_t)(WPA2_KEY_INFO_VERSION_AES | WPA2_KEY_INFO_KEY_TYPE_PAIRWISE | WPA2_KEY_INFO_ACK |
                       WPA2_KEY_INFO_MIC | WPA2_KEY_INFO_SECURE | WPA2_KEY_INFO_INSTALL |
                       WPA2_KEY_INFO_ENCR_KEY_DATA),
            s->wpa2_replay_counter,
            s->wpa2_anonce,
            wrapped,
            (uint16_t)wrapped_len,
            s->wpa2_ptk /* KCK is first 16 bytes */);

        if (msg3_len == 0) {
            return false;
        }
        if (esp32_wifi_debug_enabled()) {
            printf("QEMU: WPA2 msg3 tx replay=%" PRIu64 " key_data_len=%zu\n",
                   s->wpa2_replay_counter,
                   wrapped_len);
        }
        esp32_wpa2_send_eapol(s, msg3, msg3_len, ap->sigstrength);
        s->wpa2_state = 2; /* WAIT_M4 */
        return true;
    }

    if (s->wpa2_state == 2) {
        /* Expect message 4 */
        if ((key_info & (WPA2_KEY_INFO_MIC | WPA2_KEY_INFO_SECURE | WPA2_KEY_INFO_KEY_TYPE_PAIRWISE)) !=
            (WPA2_KEY_INFO_MIC | WPA2_KEY_INFO_SECURE | WPA2_KEY_INFO_KEY_TYPE_PAIRWISE)) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: WPA2 msg4 reject: key_info=0x%04x\n", key_info);
            }
            return false;
        }
        if (replay != s->wpa2_replay_counter) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: WPA2 msg4 reject: replay=%" PRIu64 " expected=%" PRIu64 "\n",
                       replay,
                       s->wpa2_replay_counter);
            }
            return false;
        }
        if (key_data_len != 0) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: WPA2 msg4 reject: key_data_len=%u\n", key_data_len);
            }
            return false;
        }

        uint8_t tmp[256];
        if (eapol_len > sizeof(tmp)) {
            return false;
        }
        memcpy(tmp, eapol, eapol_len);
        memset(&tmp[WPA2_EAPOL_KEY_MIC_OFF], 0, 16);
        uint8_t mic[16];
        esp32_wpa2_compute_mic(s->wpa2_ptk, tmp, eapol_len, mic);
        if (memcmp(mic, &eapol[WPA2_EAPOL_KEY_MIC_OFF], 16) != 0) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: WPA2 msg4 reject: MIC mismatch\n");
            }
            return false;
        }

        s->wpa2_handshake_done = 1;
        s->wpa2_state = 3;
        if (esp32_wifi_debug_enabled()) {
            printf("QEMU: WPA2 handshake complete\n");
        }
        return true;
    }

    return false;
}

static void Esp32_WLAN_beacon_timer(void *opaque)
{
    struct mac80211_frame *frame;
    Esp32WifiState *s = (Esp32WifiState *)opaque;

    // only send a beacon if we are an access point
    if(s->ap_state!=Esp32_WLAN__STATE_STA_ASSOCIATED) {
        if (access_points[s->beacon_ap].channel==esp32_wifi_channel) {
            if (esp32_wifi_debug_beacons_enabled()) {
                printf("QEMU: sending beacon for AP %s\n", access_points[s->beacon_ap].ssid);
            }
            memcpy(s->ap_macaddr,access_points[s->beacon_ap].mac_address,6);
            frame = Esp32_WLAN_create_beacon_frame(&access_points[s->beacon_ap]);
            memcpy(frame->receiver_address, BROADCAST, 6);
            memcpy(frame->transmitter_address, s->ap_macaddr, 6);
            memcpy(frame->address_3, s->ap_macaddr, 6);
            Esp32_WLAN_init_ap_frame(s, frame);
            Esp32_WLAN_insert_frame(s, frame);
        }
        s->beacon_ap=(s->beacon_ap+1)%nb_aps;
    }
    timer_mod(s->beacon_timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + BEACON_TIME);
}

static void Esp32_WLAN_inject_timer(void *opaque)
{
    Esp32WifiState *s = (Esp32WifiState *)opaque;
    struct mac80211_frame *frame;

    frame = s->inject_queue;
    if (frame) {
        // remove from queue
        s->inject_queue_size--;
        s->inject_queue = frame->next_frame;
        Esp32_sendFrame(s, (void *)frame, frame->frame_length,frame->signal_strength);
        free(frame);
    }
    if (s->inject_queue_size > 0) {
        // there are more packets... schedule
        // the timer for sending them as well
        timer_mod(s->inject_timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + INTER_FRAME_TIME);
    } else {
        // we wait until a new packet schedules
        // us again
        s->inject_timer_running = 0;
    }

}

static void macprint(uint8_t *p, const char * name) {
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n",name, p[0],p[1],p[2],p[3],p[4],p[5]);
}

static void infoprint(struct mac80211_frame *frame) {
    if(DEBUG_DUMPFRAMES) {
        printf("Frame Info type=%d subtype=%d to_ds=%d from_ds=%d duration=%d frame_length=%d\n",frame->frame_control.type,frame->frame_control.sub_type, frame->frame_control.to_ds,frame->frame_control.from_ds, frame->duration_id, frame->frame_length);
        macprint(frame->receiver_address,   "receiver   ");
        macprint(frame->transmitter_address,"transmitter");
        macprint(frame->address_3,          "3rd address");
        uint8_t *b=(uint8_t *)frame;
        for(int i=0;i<frame->frame_length;i++) {
            if((i%16)==0) printf("\n%04x: ",i);
            printf("%02x ",b[i]);
        }
        printf("\n");
    }
}

static void macprint_compact(const uint8_t *p, const char *name)
{
    printf("%s%02x:%02x:%02x:%02x:%02x:%02x\n",
           name,
           p[0], p[1], p[2], p[3], p[4], p[5]);
}

static size_t esp32_wifi_data_llc_offset(const struct mac80211_frame *frame)
{
    if (frame->frame_control.type != IEEE80211_TYPE_DATA) {
        return 0;
    }
    if (frame->frame_control.sub_type == IEEE80211_TYPE_DATA_SUBTYPE_QOS_DATA) {
        /* QoS Control field precedes LLC/SNAP. */
        return 2;
    }
    return 0;
}

static bool esp32_wifi_data_parse_llc(const struct mac80211_frame *frame,
                                     const uint8_t **llc_out,
                                     size_t *payload_len_out)
{
    const size_t llc_off = esp32_wifi_data_llc_offset(frame);
    const size_t mac_hdr_len = IEEE80211_HEADER_SIZE + llc_off;
    const size_t llc_snap_len = 8;
    const size_t fcs_len = 4;

    if (frame->frame_length < mac_hdr_len + llc_snap_len) {
        return false;
    }

    size_t payload_len;
    if (frame->frame_length >= mac_hdr_len + llc_snap_len + fcs_len) {
        payload_len = frame->frame_length - (mac_hdr_len + llc_snap_len + fcs_len);
    } else {
        /* Some TX paths omit FCS. */
        payload_len = frame->frame_length - (mac_hdr_len + llc_snap_len);
    }

    *llc_out = &frame->data_and_fcs[llc_off];
    *payload_len_out = payload_len;
    return true;
}

/*
 * QEMU currently sees WPA2/CCMP-protected outgoing frames from the firmware
 * before the hardware CCMP engine runs. The frames therefore include the
 * Protected bit and an 8-byte CCMP header, but the payload bytes are still
 * plaintext (LLC/SNAP + ethertype + payload). Parse those frames by skipping
 * the CCMP header and ignoring any trailing MIC/FCS bytes.
 */
static bool esp32_wifi_data_parse_protected_plain_llc(const struct mac80211_frame *frame,
                                                      const uint8_t **llc_out,
                                                      size_t *payload_len_out)
{
    const size_t qos_off = esp32_wifi_data_llc_offset(frame);
    const size_t mac_hdr_len = IEEE80211_HEADER_SIZE + qos_off;
    const size_t llc_off = qos_off + CCMP_HDR_LEN;
    const size_t llc_snap_len = 8;

    const struct {
        size_t mic_len;
        size_t fcs_len;
    } trailers[] = {
        {CCMP_MIC_LEN, 4},
        {CCMP_MIC_LEN, 0},
        {0, 4},
        {0, 0},
    };

    if (frame->frame_length < mac_hdr_len + CCMP_HDR_LEN + llc_snap_len) {
        return false;
    }

    const uint8_t *llc = &frame->data_and_fcs[llc_off];
    for (size_t i = 0; i < G_N_ELEMENTS(trailers); i++) {
        const size_t mic_len = trailers[i].mic_len;
        const size_t fcs_len = trailers[i].fcs_len;
        if (frame->frame_length < mac_hdr_len + CCMP_HDR_LEN + llc_snap_len + mic_len + fcs_len) {
            continue;
        }

        const size_t payload_len = frame->frame_length -
                                   (mac_hdr_len + CCMP_HDR_LEN + llc_snap_len + mic_len + fcs_len);
        *llc_out = llc;
        *payload_len_out = payload_len;
        return true;
    }

    return false;
}

static bool esp32_wifi_frame_is_protected(const struct mac80211_frame *frame)
{
    /* Frame Control "Protected Frame" bit is bit 14. In this struct it lives in _flags bit 4. */
    return (frame->frame_control._flags & 0x10u) != 0;
}

void Esp32_WLAN_insert_frame(Esp32WifiState *s, struct mac80211_frame *frame)
{
    struct mac80211_frame *i_frame;

    insertCRC(frame);
    if (esp32_wifi_debug_enabled()) {
        const bool is_beacon = (frame->frame_control.type == IEEE80211_TYPE_MGT) &&
                               (frame->frame_control.sub_type == IEEE80211_TYPE_MGT_SUBTYPE_BEACON);
        if (!is_beacon || esp32_wifi_debug_beacons_enabled()) {
            printf("QEMU: sent frame (qemu AP -> ESP32) type=%d subtype=%d\n",
                   frame->frame_control.type,
                   frame->frame_control.sub_type);
        }
    }
    infoprint(frame);
    s->inject_queue_size++;
    i_frame = s->inject_queue;
    if (!i_frame) {
        s->inject_queue = frame;
    } else {
        while (i_frame->next_frame) {
            i_frame = i_frame->next_frame;
        }
        i_frame->next_frame = frame;
    }

    if (!s->inject_timer_running) {
        // if the injection timer is not
        // running currently, let's schedule
        // one run...
        s->inject_timer_running = 1;
        timer_mod(s->inject_timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + INTER_FRAME_TIME);
    }

}

static _Bool Esp32_WLAN_can_receive(NetClientState *ncs)
{
    Esp32WifiState *s = qemu_get_nic_opaque(ncs);

    if (s->ap_state != Esp32_WLAN__STATE_ASSOCIATED  && s->ap_state != Esp32_WLAN__STATE_STA_ASSOCIATED) {
        // we are currently not connected
        // to the access point
        return 0;
    }
    if (s->inject_queue_size > Esp32_WLAN__MAX_INJECT_QUEUE_SIZE) {
        // overload, please give me some time...
        return 0;
    }

    return 1;
}

static ssize_t Esp32_WLAN_receive(NetClientState *ncs,
                                    const uint8_t *buf, size_t size)
{
    Esp32WifiState *s = qemu_get_nic_opaque(ncs);
    struct mac80211_frame *frame;
    if (!Esp32_WLAN_can_receive(ncs)) {
        // this should not happen, but in
        // case it does, let's simply drop
        // the packet
        return -1;
    }

    if (!s) {
        return -1;
    }
    /*
     * A 802.3 packet comes from the qemu network. The
     * access points turns it into a 802.11 frame and
     * forwards it to the wireless device
     */
    frame = Esp32_WLAN_create_data_packet(s, buf, size);
    if (frame) {
        if (s->wpa2_enabled && !s->wpa2_handshake_done) {
            free(frame);
            return (ssize_t)size;
        }
        /* send message to ESP32 AP */
        if(s->ap_state == Esp32_WLAN__STATE_STA_ASSOCIATED) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: Esp32_WLAN_create_data_packet not yet implemented for STA!\n");
            }
            frame->frame_control.to_ds = 1;
            frame->frame_control.from_ds = 0;
            memcpy(frame->receiver_address, s->ap_macaddr, 6); // ?
            // TODO implement setting all 3 802.11 MAC addresses
        }
        else { // send message to ESP32 station
            frame->frame_control.to_ds = 0;
            frame->frame_control.from_ds = 1;
            memcpy(frame->receiver_address, &buf[0], 6);
            memcpy(frame->transmitter_address, s->associated_ap_macaddr, 6);
            memcpy(frame->address_3, &buf[6], 6); // source address

            if (s->wpa2_enabled && s->wpa2_handshake_done) {
                /*
                 * Match the firmware TX format: Protected bit set and a CCMP
                 * header present, but payload still plaintext (pre-hardware
                 * CCMP offload). This keeps stock firmware happy without us
                 * needing to implement full CCMP encrypt/decrypt.
                 */
                const bool group = (buf[0] & 0x01u) != 0;
                uint64_t *pn_counter = group ? &s->wpa2_tx_pn_group : &s->wpa2_tx_pn;
                const uint64_t pn = ++(*pn_counter);

                uint8_t pn_bytes[6];
                esp32_ccmp_pn_to_bytes(pn, pn_bytes);

                uint8_t ccmp_hdr[CCMP_HDR_LEN];
                const uint8_t keyid = group ? (s->wpa2_group_keyid ? s->wpa2_group_keyid : 1) : 0;
                esp32_ccmp_build_header(ccmp_hdr, pn_bytes, keyid);

                const size_t plain_len = (size_t)frame->frame_length - IEEE80211_HEADER_SIZE;
                if (plain_len + CCMP_HDR_LEN + CCMP_MIC_LEN <= sizeof(frame->data_and_fcs)) {
                    memmove(&frame->data_and_fcs[CCMP_HDR_LEN], &frame->data_and_fcs[0], plain_len);
                    memcpy(&frame->data_and_fcs[0], ccmp_hdr, CCMP_HDR_LEN);
                    memset(&frame->data_and_fcs[CCMP_HDR_LEN + plain_len], 0, CCMP_MIC_LEN);
                    frame->frame_control._flags |= 0x10u; /* Protected */
                    frame->frame_length = IEEE80211_HEADER_SIZE +
                                          (unsigned int)(CCMP_HDR_LEN + plain_len + CCMP_MIC_LEN);
                }
            }
        }
        Esp32_WLAN_init_ap_frame(s, frame);
        Esp32_WLAN_insert_frame(s, frame);
    }
    return size;
}
static void Esp32_WLAN_cleanup(NetClientState *ncs) { }

static NetClientInfo net_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = Esp32_WLAN_can_receive,
    .receive = Esp32_WLAN_receive,
    .cleanup = Esp32_WLAN_cleanup,
};

void Esp32_WLAN_setup_ap(DeviceState *dev,Esp32WifiState *s) {

    s->ap_state = Esp32_WLAN__STATE_NOT_AUTHENTICATED;
    s->beacon_ap=0;
    esp32_wpa2_reset(s);

    const char *wpa2_ssid = getenv("ESP32_WIFI_WPA2_SSID");
    if (wpa2_ssid && wpa2_ssid[0] != '\0') {
        access_points[0].ssid = wpa2_ssid;
    }
    const char *wpa2_psk = getenv("ESP32_WIFI_WPA2_PSK");
    if (wpa2_psk && wpa2_psk[0] != '\0') {
        access_points[0].psk = wpa2_psk;
    }
    memcpy(s->ap_macaddr,(uint8_t[]){0x01,0x13,0x46,0xbf,0x31,0x50},sizeof(s->ap_macaddr));
    /* Keep the emulated NIC MAC aligned with the ESP32's factory eFuse MAC.
     * See tools/flash/gen_qemu_efuse_esp32.py (default: 02:00:00:00:00:01). */
    memcpy(s->macaddr,(uint8_t[]){0x02,0x00,0x00,0x00,0x00,0x01},sizeof(s->macaddr));

    s->inject_timer_running = 0;
    s->inject_sequence_number = 0;

    s->inject_queue = NULL;
    s->inject_queue_size = 0;

    s->beacon_timer = timer_new_ns(QEMU_CLOCK_REALTIME, Esp32_WLAN_beacon_timer, s);
    timer_mod(s->beacon_timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME)+100000000);

    // setup the timer but only schedule
    // it when necessary...
    s->inject_timer = timer_new_ns(QEMU_CLOCK_REALTIME, Esp32_WLAN_inject_timer, s);

    s->nic = qemu_new_nic(&net_info, &s->conf, object_get_typename(OBJECT(s)), dev->id, &dev->mem_reentrancy_guard, s);
    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->macaddr);
}

static void send_single_frame(Esp32WifiState *s, struct mac80211_frame *frame, struct mac80211_frame *reply) {
    reply->sequence_control.sequence_number = s->inject_sequence_number++ +0x730;
    reply->signal_strength=-10;

    if(frame) {
        memcpy(reply->receiver_address, frame->transmitter_address, 6);
        memcpy(reply->transmitter_address, s->macaddr, 6);
        memcpy(reply->address_3, frame->transmitter_address, 6);
    }

    Esp32_WLAN_insert_frame(s, reply);
}
void Esp32_WLAN_handle_frame(Esp32WifiState *s, struct mac80211_frame *frame)
{
    struct mac80211_frame *reply = NULL;
    static access_point_info dummy_ap={0};
    char ssid[64];
    unsigned char ethernet_frame[1518] = {0};
    bool start_wpa2_after_reply = false;
    if (esp32_wifi_debug_enabled()) {
        printf(
            "QEMU: received frame (esp32 -> qemu) type=%d subtype=%d chan=%d to_ds=%d from_ds=%d state=%d\n",
            frame->frame_control.type,
            frame->frame_control.sub_type,
            esp32_wifi_channel,
            frame->frame_control.to_ds,
            frame->frame_control.from_ds,
            s->ap_state
        );
        macprint_compact(frame->receiver_address, "QEMU:  ra=");
        macprint_compact(frame->transmitter_address, "QEMU:  ta=");
        macprint_compact(frame->address_3, "QEMU:  a3=");
    }
    infoprint(frame);
    access_point_info *ap_info = NULL;
    const int ap_by_mac = esp32_find_ap_by_mac(frame->receiver_address);
    if (ap_by_mac >= 0) {
        ap_info = &access_points[ap_by_mac];
    } else {
        for (int i = 0; i < nb_aps; i++) {
            if (access_points[i].channel == esp32_wifi_channel) {
                if (esp32_wifi_debug_enabled()) {
                    printf("QEMU: matching ap found: %s\n", access_points[i].ssid);
                }
                ap_info = &access_points[i];
                break;
            }
        }
    }

    if(frame->frame_control.type == IEEE80211_TYPE_MGT) {
        switch(frame->frame_control.sub_type) {
            case IEEE80211_TYPE_MGT_SUBTYPE_BEACON:
                if(s->ap_state==Esp32_WLAN__STATE_NOT_AUTHENTICATED || s->ap_state==Esp32_WLAN__STATE_AUTHENTICATED) {
                    strncpy(ssid,(char *)frame->data_and_fcs+14,frame->data_and_fcs[13]);
                    if (esp32_wifi_debug_enabled()) {
                        printf("QEMU: beacon from %s\n", ssid);
                    }
                    dummy_ap.ssid=ssid;
                    s->ap_state=Esp32_WLAN__STATE_STA_NOT_AUTHENTICATED;
                    send_single_frame(s,frame,Esp32_WLAN_create_probe_request(&dummy_ap));
                }
                break;
            case IEEE80211_TYPE_MGT_SUBTYPE_PROBE_RESP:
                ap_info=&dummy_ap;
                strncpy(ssid,(char *)frame->data_and_fcs+14,frame->data_and_fcs[13]);
                if (esp32_wifi_debug_enabled()) {
                    printf("QEMU: probe resp from %s\n", ssid);
                }
                dummy_ap.ssid=ssid;
                s->ap_state=Esp32_WLAN__STATE_STA_NOT_AUTHENTICATED;
                send_single_frame(s,frame,Esp32_WLAN_create_deauthentication());
                send_single_frame(s,frame,Esp32_WLAN_create_authentication_request());
                break;
            case IEEE80211_TYPE_MGT_SUBTYPE_ASSOCIATION_RESP:
                if (esp32_wifi_debug_enabled()) {
                    printf("QEMU: assoc resp\n");
                }
                mac80211_frame *frame1=Esp32_WLAN_create_dhcp_discover();
                memcpy(frame1->address_3,BROADCAST,6);
                memcpy(frame1->transmitter_address,frame->receiver_address,6);
                memcpy(frame1->receiver_address,frame->transmitter_address,6);
                send_single_frame(s,0,frame1);
                s->ap_state=Esp32_WLAN__STATE_STA_DHCP;
                break;
            case IEEE80211_TYPE_MGT_SUBTYPE_DISASSOCIATION:
                DEBUG_PRINT_AP(("QEMU: Received disassociation!\n"));
                send_single_frame(s,frame,Esp32_WLAN_create_disassociation());
                if (s->ap_state == Esp32_WLAN__STATE_ASSOCIATED || s->ap_state == Esp32_WLAN__STATE_STA_ASSOCIATED) {
                    s->ap_state = Esp32_WLAN__STATE_AUTHENTICATED;
                }
                esp32_wpa2_reset(s);
                break;
            case IEEE80211_TYPE_MGT_SUBTYPE_DEAUTHENTICATION:
                DEBUG_PRINT_AP(("QEMU: Received deauthentication!\n"));
                //reply = Esp32_WLAN_create_authentication_response(ap_info);
                if (s->ap_state == Esp32_WLAN__STATE_AUTHENTICATED) {
                    s->ap_state = Esp32_WLAN__STATE_NOT_AUTHENTICATED;
                }
                esp32_wpa2_reset(s);
                break;
            case IEEE80211_TYPE_MGT_SUBTYPE_AUTHENTICATION:
                if(frame->data_and_fcs[2]==2) { // response
                    DEBUG_PRINT_AP(("QEMU: Received authentication response!\n"));
                    send_single_frame(s,frame,Esp32_WLAN_create_association_request(&dummy_ap));
                }
                break;
        }
        if(ap_info) {
            memcpy(s->ap_macaddr, ap_info->mac_address, 6);
            switch(frame->frame_control.sub_type) {
                case IEEE80211_TYPE_MGT_SUBTYPE_PROBE_REQ:
                    DEBUG_PRINT_AP(("QEMU: Received probe request!\n"));
                    reply = Esp32_WLAN_create_probe_response(ap_info);
                    break;
                case IEEE80211_TYPE_MGT_SUBTYPE_AUTHENTICATION:
                    if(frame->data_and_fcs[2]==1) { // request
                        DEBUG_PRINT_AP(("QEMU: Received authentication request!\n"));
                        reply = Esp32_WLAN_create_authentication_response(ap_info);
                        if (s->ap_state == Esp32_WLAN__STATE_NOT_AUTHENTICATED) {
                            s->ap_state = Esp32_WLAN__STATE_AUTHENTICATED;
                        }
                    }
                break;
                case IEEE80211_TYPE_MGT_SUBTYPE_ASSOCIATION_REQ:
                    DEBUG_PRINT_AP(("QEMU: Received association request!\n"));
                    reply = Esp32_WLAN_create_association_response(ap_info);
                    if (s->ap_state == Esp32_WLAN__STATE_AUTHENTICATED) {
                        s->ap_state = Esp32_WLAN__STATE_ASSOCIATED;
                        memcpy(s->associated_ap_macaddr,s->ap_macaddr,6);
                        if (ap_info->wpa2_psk) {
                            start_wpa2_after_reply = true;
                        } else {
                            esp32_wpa2_reset(s);
                        }
                    }
                    break;
            }
            if (reply) {
                reply->signal_strength=ap_info->sigstrength;
                memcpy(reply->receiver_address, frame->transmitter_address, 6);
                memcpy(reply->transmitter_address, s->ap_macaddr, 6);
                memcpy(reply->address_3, s->ap_macaddr, 6);
                Esp32_WLAN_init_ap_frame(s, reply);
                Esp32_WLAN_insert_frame(s, reply);
            }
            if (start_wpa2_after_reply) {
                (void)esp32_wpa2_start(s, ap_info, frame->transmitter_address);
            }
        }
    }
    if ((frame->frame_control.type == IEEE80211_TYPE_DATA) &&
        ((frame->frame_control.sub_type == IEEE80211_TYPE_DATA_SUBTYPE_DATA) ||
         (frame->frame_control.sub_type == IEEE80211_TYPE_DATA_SUBTYPE_QOS_DATA))) {
        const bool protected = esp32_wifi_frame_is_protected(frame);

        uint16_t ethertype = 0;
        const uint8_t *payload = NULL;
        size_t payload_len = 0;

        const uint8_t *llc = NULL;
        bool ok = false;
        if (s->ap_state == Esp32_WLAN__STATE_ASSOCIATED &&
            s->wpa2_enabled && s->wpa2_handshake_done && protected) {
            ok = esp32_wifi_data_parse_protected_plain_llc(frame, &llc, &payload_len);
            if (!ok && esp32_wifi_debug_enabled()) {
                printf("QEMU: failed to parse protected LLC/SNAP (len=%u subtype=%u)\n",
                       frame->frame_length,
                       frame->frame_control.sub_type);
            }
        } else {
            ok = esp32_wifi_data_parse_llc(frame, &llc, &payload_len);
            if (!ok && esp32_wifi_debug_enabled()) {
                printf("QEMU: failed to parse LLC/SNAP (len=%u subtype=%u)\n",
                       frame->frame_length,
                       frame->frame_control.sub_type);
            }
        }
        if (!ok) {
            return;
        }

        ethertype = ((uint16_t)llc[6] << 8) | (uint16_t)llc[7];
        payload = llc + 8;

        if (esp32_wifi_debug_enabled()) {
            printf("QEMU: data frame (esp32 -> qemu) subtype=%u protected=%d ethertype=%04x len=%zu state=%d wpa2=%d hs=%d\n",
                   frame->frame_control.sub_type,
                   protected ? 1 : 0,
                   ethertype,
                   payload_len,
                   s->ap_state,
                   s->wpa2_enabled,
                   s->wpa2_handshake_done);
        }

        if (s->ap_state == Esp32_WLAN__STATE_STA_DHCP) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: STA DHCP not implemented yet\n");
            }
            if (payload_len < sizeof(dhcp_request_t)) {
                return;
            }
            dhcp_request_t *req = (dhcp_request_t *)payload;
            // check for a dhcp offer
            if (req->dhcp.bp_options[0] == 0x35 && req->dhcp.bp_options[2] == 0x2) {
                mac80211_frame *frame1 = Esp32_WLAN_create_dhcp_request(req->dhcp.yiaddr);
                memcpy(frame1->address_3, BROADCAST, 6);
                memcpy(frame1->transmitter_address, s->macaddr, 6);
                memcpy(frame1->receiver_address, frame->transmitter_address, 6);
                send_single_frame(s, 0, frame1);
                memcpy(s->ap_macaddr, (uint8_t[]){0x10, 0x01, 0x00, 0xc4, 0x0a, 0x25}, sizeof(s->ap_macaddr));
                memcpy(s->macaddr, (uint8_t[]){0x10, 0x01, 0x00, 0xc4, 0x0a, 0x24}, sizeof(s->macaddr));
                memcpy(s->associated_ap_macaddr, s->ap_macaddr, sizeof(s->ap_macaddr));
                s->ap_state = Esp32_WLAN__STATE_STA_ASSOCIATED;
            }
        } else if (s->ap_state == Esp32_WLAN__STATE_ASSOCIATED) {
            // ESP32 to QEMU
            /*
             * The access point uses the 802.11 frame
             * and sends a 802.3 frame into the network...
             * This packet is then understandable by
             * qemu-slirp
             */

            // ethernet header type
            ethernet_frame[12] = (uint8_t)((ethertype >> 8) & 0xffu);
            ethernet_frame[13] = (uint8_t)(ethertype & 0xffu);

            // the originator the packet is the station who sent the frame
            memcpy(&ethernet_frame[6], frame->transmitter_address, 6);

            // in case of to_ds = 1 and from_ds = 0, the third address is the destination address
            memcpy(&ethernet_frame[0], frame->address_3, 6);

            if (ethertype == WPA2_EAPOL_ETHERTYPE && s->wpa2_enabled) {
                const int ap_idx = esp32_find_ap_by_mac(s->associated_ap_macaddr);
                access_point_info *cur_ap = (ap_idx >= 0) ? &access_points[ap_idx] : NULL;
                if (cur_ap) {
                    if (esp32_wifi_debug_enabled() && payload_len >= 4) {
                        const uint16_t eapol_body_len = ((uint16_t)payload[2] << 8) | (uint16_t)payload[3];
                        printf("QEMU: EAPOL rx ver=%u type=%u body_len=%u total_len=%zu\n",
                               payload[0],
                               payload[1],
                               eapol_body_len,
                               payload_len);
                    }
                    const bool handled = esp32_wpa2_handle_eapol(s, cur_ap, payload, payload_len);
                    if (esp32_wifi_debug_enabled() && !handled) {
                        printf("QEMU: WPA2 EAPOL not handled\n");
                    }
                }
                return;
            }

            if (s->wpa2_enabled && !s->wpa2_handshake_done) {
                return;
            }

            /* limit payload to max length of ethernet frame */
            if (payload_len > (sizeof(ethernet_frame) - 14)) {
                payload_len = (sizeof(ethernet_frame) - 14);
            }

            /* set ethernet data (skip LLC/SNAP header in 802.11 payload) */
            memcpy(&ethernet_frame[14], payload, payload_len);

            /* send frame */
            NetClientState *queue = qemu_get_queue(s->nic);
            if (!queue) {
                if (esp32_wifi_debug_enabled()) {
                    printf("QEMU: net queue is NULL, dropping frame\n");
                }
                return;
            }
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: forwarding ethernet frame ethertype=%02x%02x len=%zu\n",
                       ethernet_frame[12],
                       ethernet_frame[13],
                       14 + payload_len);
            }
            qemu_send_packet(queue, ethernet_frame, 14 + payload_len);
        } else if (s->ap_state == Esp32_WLAN__STATE_STA_ASSOCIATED) {
            if (esp32_wifi_debug_enabled()) {
                printf("QEMU: STA DATA, NOT IMPLEMENTED YET\n");
            }
        }
    }
}
