#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/misc/esp32_sens.h"

/* Only a tiny subset of SENS is needed to unblock typical ESP-IDF ADC flows. */

enum {
    SENS_REG_SIZE = 0x1000,
};

/* SENS_SAR_MEAS_START1_REG (DR_REG_SENS_BASE + 0x54) */
#define SENS_SAR_MEAS_START1      0x54
#define SENS_MEAS1_START_FORCE    BIT(18)
#define SENS_MEAS1_START_SAR      BIT(17)
#define SENS_MEAS1_DONE_SAR       BIT(16)
#define SENS_MEAS1_DATA_MASK      0x0000ffffu

/* SENS_SAR_MEAS_START2_REG (DR_REG_SENS_BASE + 0x94) */
#define SENS_SAR_MEAS_START2      0x94
#define SENS_MEAS2_START_FORCE    BIT(18)
#define SENS_MEAS2_START_SAR      BIT(17)
#define SENS_MEAS2_DONE_SAR       BIT(16)
#define SENS_MEAS2_DATA_MASK      0x0000ffffu

static bool esp32_sens_debug_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        enabled = getenv("ESP32_SENS_DEBUG") != NULL;
    }
    return enabled;
}

static uint64_t esp32_sens_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32SensState *s = ESP32_SENS(opaque);

    if (size != 4 || (addr & 0x3) != 0 || addr >= SENS_REG_SIZE) {
        return 0;
    }

    uint32_t r = s->mem[addr / 4];

    if (esp32_sens_debug_enabled()) {
        printf("esp32_sens_read 0x%" HWADDR_PRIx " -> 0x%08" PRIx32 "\n", addr, r);
    }

    return r;
}

static void esp32_sens_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
    Esp32SensState *s = ESP32_SENS(opaque);

    if (size != 4 || (addr & 0x3) != 0 || addr >= SENS_REG_SIZE) {
        return;
    }

    if (esp32_sens_debug_enabled()) {
        printf("esp32_sens_write 0x%" HWADDR_PRIx " <- 0x%08" PRIx64 "\n", addr, value);
    }

    switch (addr) {
    case SENS_SAR_MEAS_START1: {
        /*
         * Firmware sets MEAS1_START_SAR and then spins until MEAS1_DONE_SAR is
         * asserted. We don't emulate ADC conversion, so complete immediately.
         */
        const uint32_t prev = s->mem[addr / 4];
        const uint32_t ro_mask = SENS_MEAS1_DONE_SAR | SENS_MEAS1_DATA_MASK;
        uint32_t reg = (prev & ro_mask) | ((uint32_t)value & ~ro_mask);

        const bool start = (value & SENS_MEAS1_START_SAR) != 0;
        if (start) {
            reg &= ~SENS_MEAS1_START_SAR; /* self-clearing */
            reg &= ~SENS_MEAS1_DONE_SAR;

            /* Deterministic mid-scale sample (12-bit in practice). */
            reg = (reg & ~SENS_MEAS1_DATA_MASK) | 0x0800u;
            reg |= SENS_MEAS1_DONE_SAR;
        }

        s->mem[addr / 4] = reg;
        break;
    }
    case SENS_SAR_MEAS_START2: {
        /*
         * Firmware sets MEAS2_START_SAR and then spins until MEAS2_DONE_SAR is
         * asserted. We don't emulate ADC conversion, so complete immediately.
         */
        const uint32_t prev = s->mem[addr / 4];
        const uint32_t ro_mask = SENS_MEAS2_DONE_SAR | SENS_MEAS2_DATA_MASK;
        uint32_t reg = (prev & ro_mask) | ((uint32_t)value & ~ro_mask);

        const bool start = (value & SENS_MEAS2_START_SAR) != 0;
        if (start) {
            reg &= ~SENS_MEAS2_START_SAR; /* self-clearing */
            reg &= ~SENS_MEAS2_DONE_SAR;

            /* Deterministic mid-scale sample (12-bit in practice). */
            reg = (reg & ~SENS_MEAS2_DATA_MASK) | 0x0800u;
            reg |= SENS_MEAS2_DONE_SAR;
        }

        s->mem[addr / 4] = reg;
        break;
    }
    default:
        s->mem[addr / 4] = (uint32_t)value;
        break;
    }
}

static const MemoryRegionOps esp32_sens_ops = {
    .read = esp32_sens_read,
    .write = esp32_sens_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void esp32_sens_init(Object *obj)
{
    Esp32SensState *s = ESP32_SENS(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &esp32_sens_ops, s, TYPE_ESP32_SENS, SENS_REG_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);

    memset(s->mem, 0, sizeof(s->mem));
}

static const TypeInfo esp32_sens_info = {
    .name = TYPE_ESP32_SENS,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32SensState),
    .instance_init = esp32_sens_init,
};

static void esp32_sens_register_types(void)
{
    type_register_static(&esp32_sens_info);
}

type_init(esp32_sens_register_types)
