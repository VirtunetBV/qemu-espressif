#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "qapi/error.h"

#include "hw/misc/esp32_rmt.h"

#define ESP32_RMT_REGS_SIZE 0x1000

#define RMT_CH_CONF0_BASE 0x20
#define RMT_CH_STRIDE 0x8
#define RMT_CH_CONF1_OFFSET 0x4

#define RMT_INT_RAW_REG 0xA0
#define RMT_INT_ST_REG 0xA4
#define RMT_INT_ENA_REG 0xA8
#define RMT_INT_CLR_REG 0xAC

static bool esp32_rmt_debug_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        enabled = getenv("ESP32_RMT_DEBUG") != NULL;
    }
    return enabled;
}

static void esp32_rmt_update_irq(Esp32RmtState *s)
{
    qemu_set_irq(s->irq, (s->int_raw & s->int_ena) ? 1 : 0);
}

static void esp32_rmt_raise_tx_end(Esp32RmtState *s, int channel)
{
    /* TX_END interrupt bit is channel*3 (0, 3, 6, ...) */
    s->int_raw |= (uint32_t)1U << (channel * 3);
    if (esp32_rmt_debug_enabled()) {
        printf("esp32_rmt: TX_END ch=%d raw=0x%08" PRIx32 " ena=0x%08" PRIx32 "\n",
               channel, s->int_raw, s->int_ena);
    }
    esp32_rmt_update_irq(s);
}

static uint64_t esp32_rmt_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32RmtState *s = ESP32_RMT(opaque);
    uint32_t r = 0;

    if (size != 4 || (addr & 0x3) != 0 || addr >= ESP32_RMT_REGS_SIZE) {
        return 0;
    }

    switch (addr) {
    case RMT_INT_RAW_REG:
        r = s->int_raw;
        break;
    case RMT_INT_ST_REG:
        r = s->int_raw & s->int_ena;
        break;
    case RMT_INT_ENA_REG:
        r = s->int_ena;
        break;
    case RMT_INT_CLR_REG:
        r = 0;
        break;
    default:
        r = s->regs[addr / 4];
        break;
    }

    return r;
}

static void esp32_rmt_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
    Esp32RmtState *s = ESP32_RMT(opaque);
    uint32_t v = (uint32_t)value;

    if (size != 4 || (addr & 0x3) != 0 || addr >= ESP32_RMT_REGS_SIZE) {
        return;
    }

    switch (addr) {
    case RMT_INT_ENA_REG:
        if (esp32_rmt_debug_enabled()) {
            printf("esp32_rmt: INT_ENA <- 0x%08" PRIx32 "\n", v);
        }
        s->int_ena = v;
        esp32_rmt_update_irq(s);
        break;
    case RMT_INT_CLR_REG:
        if (esp32_rmt_debug_enabled()) {
            printf("esp32_rmt: INT_CLR <- 0x%08" PRIx32 "\n", v);
        }
        s->int_raw &= ~v;
        esp32_rmt_update_irq(s);
        break;
    default:
        s->regs[addr / 4] = v;

        /* TX start: writing conf1.tx_start should eventually trigger TX_END.
         * We do not emulate timing; we complete immediately to avoid firmware
         * deadlocks in users of the legacy RMT driver (e.g. WS2812/LED ring).
         */
        if (addr >= (RMT_CH_CONF0_BASE + RMT_CH_CONF1_OFFSET) &&
            addr < (RMT_CH_CONF0_BASE + RMT_CH_STRIDE * 8) &&
            ((addr - (RMT_CH_CONF0_BASE + RMT_CH_CONF1_OFFSET)) % RMT_CH_STRIDE == 0)) {
            int channel = (addr - (RMT_CH_CONF0_BASE + RMT_CH_CONF1_OFFSET)) / RMT_CH_STRIDE;
            if (esp32_rmt_debug_enabled()) {
                printf("esp32_rmt: CH%d_CONF1 <- 0x%08" PRIx32 "\n", channel, v);
            }
            if (v & 0x1) {
                s->regs[addr / 4] = v & ~1U;
                esp32_rmt_raise_tx_end(s, channel);
            }
        }
        break;
    }
}

static const MemoryRegionOps esp32_rmt_ops = {
    .read = esp32_rmt_read,
    .write = esp32_rmt_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void esp32_rmt_reset(DeviceState *dev)
{
    Esp32RmtState *s = ESP32_RMT(dev);

    memset(s->regs, 0, sizeof(s->regs));
    s->int_raw = 0;
    s->int_ena = 0;

    /* Reset values: conf0.mem_size defaults to 1 block for all channels. */
    for (int ch = 0; ch < 8; ++ch) {
        hwaddr conf0 = RMT_CH_CONF0_BASE + (hwaddr)ch * RMT_CH_STRIDE;
        s->regs[conf0 / 4] = (uint32_t)1U << 24;
    }

    esp32_rmt_update_irq(s);
}

static void esp32_rmt_init(Object *obj)
{
    Esp32RmtState *s = ESP32_RMT(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &esp32_rmt_ops, s, TYPE_ESP32_RMT, ESP32_RMT_REGS_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static void esp32_rmt_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_legacy_reset(dc, esp32_rmt_reset);
}

static const TypeInfo esp32_rmt_info = {
    .name = TYPE_ESP32_RMT,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32RmtState),
    .instance_init = esp32_rmt_init,
    .class_init = esp32_rmt_class_init,
};

static void esp32_rmt_register_types(void)
{
    type_register_static(&esp32_rmt_info);
}

type_init(esp32_rmt_register_types)
