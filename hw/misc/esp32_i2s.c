#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"

#include "hw/misc/esp32_i2s.h"

#define ESP32_I2S_REGS_SIZE 0x1000

#define I2S_CONF_REG 0x08

#define I2S_INT_RAW_REG 0x0C
#define I2S_INT_ST_REG 0x10
#define I2S_INT_ENA_REG 0x14
#define I2S_INT_CLR_REG 0x18

/* Interrupt bits used by common I2S TX paths (DMA EOF / DONE). */
#define I2S_INT_OUT_DONE BIT(11)
#define I2S_INT_OUT_EOF BIT(12)
#define I2S_INT_OUT_TOTAL_EOF BIT(16)

static bool esp32_i2s_debug_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        enabled = getenv("ESP32_I2S_DEBUG") != NULL;
    }
    return enabled;
}

static void esp32_i2s_update_irq(Esp32I2SState *s)
{
    qemu_set_irq(s->irq, (s->int_raw & s->int_ena) ? 1 : 0);
}

static void esp32_i2s_raise_tx_done(Esp32I2SState *s)
{
    s->int_raw |= I2S_INT_OUT_DONE | I2S_INT_OUT_EOF | I2S_INT_OUT_TOTAL_EOF;
    if (esp32_i2s_debug_enabled()) {
        printf("esp32_i2s%u: TX_DONE raw=0x%08" PRIx32 " ena=0x%08" PRIx32 "\n",
               s->id, s->int_raw, s->int_ena);
    }
    esp32_i2s_update_irq(s);
}

static uint64_t esp32_i2s_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32I2SState *s = ESP32_I2S(opaque);
    uint32_t r = 0;

    if (size != 4 || (addr & 0x3) != 0 || addr >= ESP32_I2S_REGS_SIZE) {
        return 0;
    }

    switch (addr) {
    case I2S_INT_RAW_REG:
        r = s->int_raw;
        break;
    case I2S_INT_ST_REG:
        r = s->int_raw & s->int_ena;
        break;
    case I2S_INT_ENA_REG:
        r = s->int_ena;
        break;
    case I2S_INT_CLR_REG:
        r = 0;
        break;
    default:
        r = s->regs[addr / 4];
        break;
    }

    return r;
}

static void esp32_i2s_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
    Esp32I2SState *s = ESP32_I2S(opaque);
    uint32_t v = (uint32_t)value;

    if (size != 4 || (addr & 0x3) != 0 || addr >= ESP32_I2S_REGS_SIZE) {
        return;
    }

    switch (addr) {
    case I2S_INT_ENA_REG:
        if (esp32_i2s_debug_enabled()) {
            printf("esp32_i2s%u: INT_ENA <- 0x%08" PRIx32 "\n", s->id, v);
        }
        s->int_ena = v;
        esp32_i2s_update_irq(s);
        break;
    case I2S_INT_CLR_REG:
        if (esp32_i2s_debug_enabled()) {
            printf("esp32_i2s%u: INT_CLR <- 0x%08" PRIx32 "\n", s->id, v);
        }
        s->int_raw &= ~v;
        esp32_i2s_update_irq(s);
        break;
    default:
        s->regs[addr / 4] = v;
        if (addr == I2S_CONF_REG && (v & BIT(4))) { /* I2S_TX_START */
            if (esp32_i2s_debug_enabled()) {
                printf("esp32_i2s%u: CONF <- 0x%08" PRIx32 " (TX_START)\n", s->id, v);
            }
            s->regs[addr / 4] = v & ~BIT(4);
            esp32_i2s_raise_tx_done(s);
        }
        break;
    }
}

static const MemoryRegionOps esp32_i2s_ops = {
    .read = esp32_i2s_read,
    .write = esp32_i2s_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void esp32_i2s_reset(DeviceState *dev)
{
    Esp32I2SState *s = ESP32_I2S(dev);
    memset(s->regs, 0, sizeof(s->regs));
    s->int_raw = 0;
    s->int_ena = 0;
    esp32_i2s_update_irq(s);
}

static void esp32_i2s_init(Object *obj)
{
    Esp32I2SState *s = ESP32_I2S(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &esp32_i2s_ops, s, TYPE_ESP32_I2S, ESP32_I2S_REGS_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static Property esp32_i2s_properties[] = {
    DEFINE_PROP_UINT32("id", Esp32I2SState, id, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void esp32_i2s_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_props(dc, esp32_i2s_properties);
    device_class_set_legacy_reset(dc, esp32_i2s_reset);
}

static const TypeInfo esp32_i2s_info = {
    .name = TYPE_ESP32_I2S,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32I2SState),
    .instance_init = esp32_i2s_init,
    .class_init = esp32_i2s_class_init,
};

static void esp32_i2s_register_types(void)
{
    type_register_static(&esp32_i2s_info);
}

type_init(esp32_i2s_register_types)
