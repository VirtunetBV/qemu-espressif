#pragma once

#include "hw/hw.h"
#include "hw/sysbus.h"

#define TYPE_ESP32_RMT "misc.esp32.rmt"
#define ESP32_RMT(obj) OBJECT_CHECK(Esp32RmtState, (obj), TYPE_ESP32_RMT)

typedef struct Esp32RmtState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;

    uint32_t regs[0x1000 / sizeof(uint32_t)];
    uint32_t int_raw;
    uint32_t int_ena;
} Esp32RmtState;

