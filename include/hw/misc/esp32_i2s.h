#pragma once

#include "hw/hw.h"
#include "hw/sysbus.h"

#define TYPE_ESP32_I2S "misc.esp32.i2s"
#define ESP32_I2S(obj) OBJECT_CHECK(Esp32I2SState, (obj), TYPE_ESP32_I2S)

typedef struct Esp32I2SState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;

    uint32_t id;
    uint32_t regs[0x1000 / sizeof(uint32_t)];
    uint32_t int_raw;
    uint32_t int_ena;
} Esp32I2SState;

