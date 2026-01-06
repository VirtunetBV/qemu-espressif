#pragma once

#include "hw/hw.h"
#include "hw/sysbus.h"

#define TYPE_ESP32_SENS "misc.esp32.sens"
#define ESP32_SENS(obj) OBJECT_CHECK(Esp32SensState, (obj), TYPE_ESP32_SENS)

typedef struct Esp32SensState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;

    uint32_t mem[0x1000 / sizeof(uint32_t)];
} Esp32SensState;

