/*
 * ESP32 GPIO emulation
 *
 * Copyright (c) 2019 Espressif Systems (Shanghai) Co. Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 or
 * (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/registerfields.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/gpio/esp32_gpio.h"



static uint64_t esp32_gpio_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32GpioState *s = ESP32_GPIO(opaque);
    uint64_t r = 0;

    if ((addr % sizeof(uint32_t)) != 0 || addr >= ESP32_GPIO_MEM_SIZE) {
        return 0;
    }

    uint32_t *reg = &s->mem[addr / sizeof(uint32_t)];
    r = *reg;
    switch (addr) {
    case A_GPIO_STRAP:
        r = s->strap_mode;
        break;
    case A_GPIO_IN:
        /*
         * Input reflects output level when the pin is configured as an output.
         * Otherwise, fall back to the externally provided input level.
         */
        r = (s->mem[A_GPIO_OUT / sizeof(uint32_t)] &
             s->mem[A_GPIO_ENABLE / sizeof(uint32_t)]) |
            (s->input0 & ~s->mem[A_GPIO_ENABLE / sizeof(uint32_t)]);
        break;
    case A_GPIO_IN1:
        r = (s->mem[A_GPIO_OUT1 / sizeof(uint32_t)] &
             s->mem[A_GPIO_ENABLE1 / sizeof(uint32_t)]) |
            (s->input1 & ~s->mem[A_GPIO_ENABLE1 / sizeof(uint32_t)]);
        break;

    default:
        break;
    }
    return r;
}

static void esp32_gpio_write(void *opaque, hwaddr addr,
                       uint64_t value, unsigned int size)
{
    Esp32GpioState *s = ESP32_GPIO(opaque);
    if ((addr % sizeof(uint32_t)) != 0 || addr >= ESP32_GPIO_MEM_SIZE) {
        return;
    }

    uint32_t v = (uint32_t)value;
    switch (addr) {
    case A_GPIO_OUT:
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_OUT_W1TS:
        s->mem[A_GPIO_OUT / sizeof(uint32_t)] |= v;
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_OUT_W1TC:
        s->mem[A_GPIO_OUT / sizeof(uint32_t)] &= ~v;
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_OUT1:
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_OUT1_W1TS:
        s->mem[A_GPIO_OUT1 / sizeof(uint32_t)] |= v;
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_OUT1_W1TC:
        s->mem[A_GPIO_OUT1 / sizeof(uint32_t)] &= ~v;
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_ENABLE:
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_ENABLE_W1TS:
        s->mem[A_GPIO_ENABLE / sizeof(uint32_t)] |= v;
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_ENABLE_W1TC:
        s->mem[A_GPIO_ENABLE / sizeof(uint32_t)] &= ~v;
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_ENABLE1:
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_ENABLE1_W1TS:
        s->mem[A_GPIO_ENABLE1 / sizeof(uint32_t)] |= v;
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_ENABLE1_W1TC:
        s->mem[A_GPIO_ENABLE1 / sizeof(uint32_t)] &= ~v;
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    case A_GPIO_STATUS_W1TS:
        s->mem[A_GPIO_STATUS / sizeof(uint32_t)] |= v;
        break;
    case A_GPIO_STATUS_W1TC:
        s->mem[A_GPIO_STATUS / sizeof(uint32_t)] &= ~v;
        break;
    case A_GPIO_STATUS1_W1TS:
        s->mem[A_GPIO_STATUS1 / sizeof(uint32_t)] |= v;
        break;
    case A_GPIO_STATUS1_W1TC:
        s->mem[A_GPIO_STATUS1 / sizeof(uint32_t)] &= ~v;
        break;
    default:
        s->mem[addr / sizeof(uint32_t)] = v;
        break;
    }
}

static const MemoryRegionOps uart_ops = {
    .read =  esp32_gpio_read,
    .write = esp32_gpio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void esp32_gpio_reset_hold(Object *obj, ResetType type)
{
    Esp32GpioState *s = ESP32_GPIO(obj);
    memset(s->mem, 0, sizeof(s->mem));
}

static void esp32_gpio_realize(DeviceState *dev, Error **errp)
{
}

static void esp32_gpio_init(Object *obj)
{
    Esp32GpioState *s = ESP32_GPIO(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    /* Set the default value for the strap_mode property */
    object_property_set_int(obj, "strap_mode", ESP32_STRAP_MODE_FLASH_BOOT, &error_fatal);
    memset(s->mem, 0, sizeof(s->mem));
    s->input0 = 0xffffffff;
    s->input1 = 0xffffffff;

    memory_region_init_io(&s->iomem, obj, &uart_ops, s,
                          TYPE_ESP32_GPIO, 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static Property esp32_gpio_properties[] = {
    /* The strap_mode needs to be explicitly set in the instance init, thus, set
     * the default value to 0. */
    DEFINE_PROP_UINT32("strap_mode", Esp32GpioState, strap_mode, 0),
    DEFINE_PROP_UINT32("input0", Esp32GpioState, input0, 0xffffffff),
    DEFINE_PROP_UINT32("input1", Esp32GpioState, input1, 0xffffffff),
    DEFINE_PROP_END_OF_LIST(),
};

static void esp32_gpio_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    rc->phases.hold = esp32_gpio_reset_hold;
    dc->realize = esp32_gpio_realize;
    device_class_set_props(dc, esp32_gpio_properties);
}

static const TypeInfo esp32_gpio_info = {
    .name = TYPE_ESP32_GPIO,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32GpioState),
    .instance_init = esp32_gpio_init,
    .class_init = esp32_gpio_class_init,
    .class_size = sizeof(Esp32GpioClass),
};

static void esp32_gpio_register_types(void)
{
    type_register_static(&esp32_gpio_info);
}

type_init(esp32_gpio_register_types)
