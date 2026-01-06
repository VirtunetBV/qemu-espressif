#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu/guest-random.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "hw/hw.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "hw/misc/esp32_wifi.h"
#include "exec/address-spaces.h"
#include "esp32_wlan_packet.h"
#include "hw/qdev-properties.h"

static bool esp32_wifi_debug_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        enabled = getenv("ESP32_WIFI_DEBUG") != NULL;
    }
    return enabled;
}

static uint64_t esp32_wifi_read(void *opaque, hwaddr addr, unsigned int size)
{

    Esp32WifiState *s = ESP32_WIFI(opaque);
    uint32_t r = s->mem[addr/4];

    switch(addr) {
        case A_WIFI_DMA_IN_STATUS:
            r = s->mem[addr / 4];
            break;
        case A_WIFI_DMA_INT_STATUS:
        case A_WIFI_DMA_INT_CLR:
            r=s->raw_interrupt;
            break;
        case A_WIFI_STATUS:
        case A_WIFI_DMA_OUT_STATUS:
            r=1;
            break;
    }

    if (esp32_wifi_debug_enabled()) {
        printf("esp32_wifi_read 0x%" HWADDR_PRIx " -> 0x%08" PRIx32 "\n", addr, r);
    }

    return r;
}
static void set_interrupt(Esp32WifiState *s, int e) {
    s->raw_interrupt |= e;
    qemu_set_irq(s->irq, 1);
}

static void esp32_wifi_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size) {
    Esp32WifiState *s = ESP32_WIFI(opaque);
    if (esp32_wifi_debug_enabled()) {
        printf("esp32_wifi_write 0x%" HWADDR_PRIx " <- 0x%" PRIx64 "\n", addr, value);
    }

    switch (addr) {
        case A_WIFI_DMA_IN_STATUS:
            /* W1C style: clear written bits */
            s->mem[addr / 4] &= ~(uint32_t)value;
            return;
        case A_WIFI_DMA_INLINK:
            s->dma_inlink_address = value;
            break;
        case A_WIFI_DMA_INT_CLR:
            s->raw_interrupt &= ~value;
            if (s->raw_interrupt == 0)
                qemu_set_irq(s->irq, 0);
            break;
        case A_WIFI_DMA_OUTLINK:
            if (value & 0xc0000000) {
                // do a DMA transfer to the hardware from esp32 memory
                mac80211_frame frame;
                dma_list_item item;
                unsigned memaddr = (0x3ff00000 | (value & 0xfffff));
                address_space_read(&address_space_memory, memaddr, MEMTXATTRS_UNSPECIFIED, &item, 12);
                address_space_read(&address_space_memory, item.address, MEMTXATTRS_UNSPECIFIED, &frame, item.length);
                // frame from esp32 to ap
                frame.frame_length=item.length;
                frame.next_frame=0;
                Esp32_WLAN_handle_frame(s, &frame);
                set_interrupt(s, 0x80);
            }
    }
    s->mem[addr/4]=value;
}

static int match_mac_address(uint8_t *a1,uint8_t *a2) {
    if(!memcmp(a1,a2,6)) return 1;
    if(!memcmp(a1,BROADCAST,6)) return 1;
    return 0;
}

static void esp32_wifi_get_mac_from_regs(Esp32WifiState *s, hwaddr lo_reg, hwaddr hi_reg, uint8_t out[6])
{
    const uint32_t lo = s->mem[lo_reg / 4];
    const uint32_t hi = s->mem[hi_reg / 4];

    out[0] = (uint8_t)(lo & 0xffu);
    out[1] = (uint8_t)((lo >> 8) & 0xffu);
    out[2] = (uint8_t)((lo >> 16) & 0xffu);
    out[3] = (uint8_t)((lo >> 24) & 0xffu);
    out[4] = (uint8_t)(hi & 0xffu);
    out[5] = (uint8_t)((hi >> 8) & 0xffu);
}

// frame from QEMU to ESP32
void Esp32_sendFrame(Esp32WifiState *s, mac80211_frame *frame, int length, int signal_strength) {

    if(s->dma_inlink_address == 0) {
        return;
    }
    const size_t rx_ctrl_len = sizeof(wifi_pkt_rx_ctrl_t);
    size_t header_len = rx_ctrl_len + (size_t)length;
    uint8_t *header = g_malloc(header_len);
    wifi_pkt_rx_ctrl_t *pkt=(wifi_pkt_rx_ctrl_t *)header;
    *pkt=(wifi_pkt_rx_ctrl_t){
        .rssi=(signal_strength+(rand()%10)+96),
        .rate=11,
        .sig_len=length,
        .sig_len_copy=length,
        .legacy_length=length,
        .noise_floor=-97,
        .channel=esp32_wifi_channel,
        .timestamp=qemu_clock_get_ns(QEMU_CLOCK_REALTIME)/1000,
    };
    // These 4 bits are set if the mac addresses previously stored at 0x40 and 0x48
    // match the destination or bssid addresses in the frame
    uint8_t addr0[6];
    uint8_t addr1[6];
    esp32_wifi_get_mac_from_regs(s, 0x40, 0x44, addr0);
    esp32_wifi_get_mac_from_regs(s, 0x48, 0x4c, addr1);

    if (match_mac_address(frame->receiver_address, addr0)) {
        pkt->damatch0 = 1;
    }
    if (match_mac_address(frame->receiver_address, addr1)) {
        pkt->damatch1 = 1;
    }
    if (match_mac_address(frame->address_3, addr0)) {
        pkt->bssidmatch0 = 1;
    }
    if (match_mac_address(frame->address_3, addr1)) {
        pkt->bssidmatch1 = 1;
    }
    //printf("...%x %x\n",header[3],frame->receiver_address[0]);

    memcpy(header + rx_ctrl_len, frame, length);
    length += (int)rx_ctrl_len;
    // do a DMA transfer from the hardware to esp32 memory
    dma_list_item item;
    const uint32_t desc_addr = (uint32_t)s->dma_inlink_address;
    address_space_read(&address_space_memory, desc_addr, MEMTXATTRS_UNSPECIFIED, &item, 12);
    address_space_write(&address_space_memory, item.address, MEMTXATTRS_UNSPECIFIED, header, length);
    item.length=length;
    item.eof=1;
    item.owner = 0;
    address_space_write(&address_space_memory, desc_addr, MEMTXATTRS_UNSPECIFIED,&item,4);
    s->dma_inlink_address=item.next;
    s->mem[A_WIFI_DMA_IN_STATUS / 4] |= 0x1; /* RX EOF */
    /* Common ESP32 DMA status regs observed during RX handling. */
    s->mem[0x8c / 4] = desc_addr; /* inlink_dscr */
    s->mem[0x90 / 4] = desc_addr; /* in_suc_eof_des_addr */
    set_interrupt(s, 0x1000024);
    g_free(header);
}

static const MemoryRegionOps esp32_wifi_ops = {
    .read =  esp32_wifi_read,
    .write = esp32_wifi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void esp32_wifi_realize(DeviceState *dev, Error **errp)
{
    Esp32WifiState *s = ESP32_WIFI(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    s->dma_inlink_address = 0;

    memory_region_init_io(&s->iomem, OBJECT(dev), &esp32_wifi_ops, s,
                          TYPE_ESP32_WIFI, 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    memset(s->mem,0,sizeof(s->mem));
    Esp32_WLAN_setup_ap(dev, s);

}
static Property esp32_wifi_properties[] = {
    DEFINE_NIC_PROPERTIES(Esp32WifiState, conf),
    DEFINE_PROP_END_OF_LIST(),
};
static void esp32_wifi_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = esp32_wifi_realize;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Esp32 WiFi";
    device_class_set_props(dc, esp32_wifi_properties);
}


static const TypeInfo esp32_wifi_info = {
    .name = TYPE_ESP32_WIFI,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32WifiState),
    .class_init    = esp32_wifi_class_init,
};

static void esp32_wifi_register_types(void)
{
    type_register_static(&esp32_wifi_info);
}

type_init(esp32_wifi_register_types)
