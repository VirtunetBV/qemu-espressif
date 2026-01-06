/*
 * ESP32 RTC_CNTL (RTC block controller) device
 *
 * Copyright (c) 2019 Espressif Systems (Shanghai) Co. Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 or
 * (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "qemu/bswap.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "hw/hw.h"
#include "hw/core/cpu.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/misc/esp32_reg.h"
#include "hw/misc/esp32_rtc_cntl.h"

static void esp32_rtc_update_cpu_stall(Esp32RtcCntlState* s);
static void esp32_rtc_update_clk(Esp32RtcCntlState* s);
static void esp32_rtc_wdt_update(Esp32RtcCntlState *s, bool reset_stage);
static void esp32_rtc_wdt_cb(void *opaque);

enum {
    RTC_WDT_STG_SEL_OFF = 0,
    RTC_WDT_STG_SEL_INT = 1,
    RTC_WDT_STG_SEL_RESET_CPU = 2,
    RTC_WDT_STG_SEL_RESET_SYSTEM = 3,
    RTC_WDT_STG_SEL_RESET_RTC = 4,
};

#define ESP32_RTC_WDT_WKEY 0x50d83aa1u

static uint32_t esp32_process_stack_pc(uint32_t pc)
{
    /* ESP32 uses a special encoding of return addresses on the stack. */
    if (pc & 0x80000000U) {
        return (pc & 0x3fffffffU) | 0x40000000U;
    }
    return pc;
}

static bool esp32_stack_ptr_is_sane(uint32_t sp)
{
    if ((sp & 0x3) != 0) {
        return false;
    }
    /*
     * Heuristic: typical ESP32 task stacks live in DRAM. This is only used for
     * debug logs, so keep it conservative.
     */
    return (sp >= 0x3ff80000U && sp < 0x40000000U);
}

static bool esp32_read_u32_debug(CPUState *cpu, uint32_t addr, uint32_t *out)
{
    uint32_t raw;
    if (cpu_memory_rw_debug(cpu, addr, &raw, sizeof(raw), false) != 0) {
        return false;
    }
    *out = le32_to_cpu(raw);
    return true;
}

static bool esp32_cpu_gdb_read_u32(CPUState *cpu, int reg, uint32_t *out)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    if (!cc || !cc->gdb_read_register || !out) {
        return false;
    }

    GByteArray *buf = g_byte_array_sized_new(sizeof(uint32_t));
    int len = cc->gdb_read_register(cpu, buf, reg);
    if (len != (int)sizeof(uint32_t) || buf->len < sizeof(uint32_t)) {
        g_byte_array_unref(buf);
        return false;
    }
    *out = ldl_le_p(buf->data);
    g_byte_array_unref(buf);
    return true;
}

static void esp32_log_backtrace(CPUState *cpu, int depth)
{
    if (!cpu || !qemu_loglevel_mask(LOG_GUEST_ERROR)) {
        return;
    }

    /*
     * Avoid target-specific CPU headers here (this file is "common code" in
     * QEMU). Use the Xtensa GDB register map instead:
     * - reg 0 is PC
     * - reg 69 is WINDOWBASE
     * - regs 1..64 are AR0..AR63 (physical regs)
     *
     * Live A0..A15 map onto AR[(WINDOWBASE * 4 + N) % 64].
     */
    uint32_t pc = 0;
    uint32_t windowbase = 0;
    if (!esp32_cpu_gdb_read_u32(cpu, 0, &pc) ||
        !esp32_cpu_gdb_read_u32(cpu, 69, &windowbase)) {
        return;
    }
    windowbase &= 0xFF;
    uint32_t sp = 0;
    uint32_t next_pc = 0;
    int a0_phys = (int)((windowbase * 4 + 0) % 64);
    int a1_phys = (int)((windowbase * 4 + 1) % 64);
    if (!esp32_cpu_gdb_read_u32(cpu, 1 + a0_phys, &next_pc) ||
        !esp32_cpu_gdb_read_u32(cpu, 1 + a1_phys, &sp)) {
        return;
    }

    char line[2048];
    size_t off = 0;
    off += snprintf(line + off, sizeof(line) - off, "Backtrace:");
    off += snprintf(line + off, sizeof(line) - off, " 0x%08x:0x%08x",
                    esp32_process_stack_pc(pc), sp);

    bool corrupted = !esp32_stack_ptr_is_sane(sp);
    for (int i = 0; i < depth && next_pc != 0 && !corrupted; ++i) {
        uint32_t base = sp;
        if (base < 16) {
            corrupted = true;
            break;
        }

        uint32_t prev_next_pc = 0;
        uint32_t prev_sp = 0;
        if (!esp32_read_u32_debug(cpu, base - 16, &prev_next_pc) ||
            !esp32_read_u32_debug(cpu, base - 12, &prev_sp)) {
            corrupted = true;
            break;
        }

        pc = next_pc;
        sp = prev_sp;
        next_pc = prev_next_pc;

        if (!esp32_stack_ptr_is_sane(sp)) {
            corrupted = true;
        }

        if (off + 32 >= sizeof(line)) {
            break;
        }
        off += snprintf(line + off, sizeof(line) - off, " 0x%08x:0x%08x",
                        esp32_process_stack_pc(pc), sp);
    }

    if (corrupted) {
        off += snprintf(line + off, sizeof(line) - off, " |<-CORRUPTED");
    } else if (next_pc != 0) {
        off += snprintf(line + off, sizeof(line) - off, " |<-CONTINUES");
    }
    qemu_log_mask(LOG_GUEST_ERROR, "%s\n", line);
}

static uint64_t esp32_rtc_cntl_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32RtcCntlState *s = ESP32_RTC_CNTL(opaque);
    uint64_t r = 0;
    switch (addr) {
    case A_RTC_CNTL_OPTIONS0:
        r = s->options0_reg;
        break;
    case A_RTC_CNTL_TIME_UPDATE:
        r = R_RTC_CNTL_TIME_UPDATE_VALID_MASK;
        break;
    case A_RTC_CNTL_TIME0:
        r = s->time_reg & UINT32_MAX;
        break;
    case A_RTC_CNTL_TIME1:
        r = s->time_reg >> 32;
        break;

    case A_RTC_CNTL_RESET_STATE:
        r = FIELD_DP32(r, RTC_CNTL_RESET_STATE, RESET_CAUSE_PROCPU, s->reset_cause[0]);
        r = FIELD_DP32(r, RTC_CNTL_RESET_STATE, RESET_CAUSE_APPCPU, s->reset_cause[1]);
        r = FIELD_DP32(r, RTC_CNTL_RESET_STATE, PROCPU_STAT_VECTOR_SEL, s->stat_vector_sel[0]);
        r = FIELD_DP32(r, RTC_CNTL_RESET_STATE, APPCPU_STAT_VECTOR_SEL, s->stat_vector_sel[1]);
        break;

    case A_RTC_CNTL_STORE0:
    case A_RTC_CNTL_STORE1:
    case A_RTC_CNTL_STORE2:
    case A_RTC_CNTL_STORE3:
        r = s->scratch_reg[(addr - A_RTC_CNTL_STORE0) / 4];
        break;

    case A_RTC_CNTL_CLK_CONF:
        r = FIELD_DP32(r, RTC_CNTL_CLK_CONF, SOC_CLK_SEL, s->soc_clk);
        r = FIELD_DP32(r, RTC_CNTL_CLK_CONF, FAST_CLK_RTC_SEL, s->rtc_fastclk);
        r = FIELD_DP32(r, RTC_CNTL_CLK_CONF, ANA_CLK_RTC_SEL, s->rtc_slowclk);
        break;

    case A_RTC_CNTL_WDTCONFIG0:
        r = s->wdtconfig0_reg;
        break;
    case A_RTC_CNTL_WDTCONFIG1:
        r = s->wdtconfig1_reg;
        break;
    case A_RTC_CNTL_WDTCONFIG2:
        r = s->wdtconfig2_reg;
        break;
    case A_RTC_CNTL_WDTCONFIG3:
        r = s->wdtconfig3_reg;
        break;
    case A_RTC_CNTL_WDTCONFIG4:
        r = s->wdtconfig4_reg;
        break;
    case A_RTC_CNTL_WDTFEED:
        r = 0;
        break;
    case A_RTC_CNTL_WDTWPROTECT:
        r = s->wdtwprotect_reg;
        break;

    case A_RTC_CNTL_SW_CPU_STALL:
        r = s->sw_cpu_stall_reg;
        break;

    case A_RTC_CNTL_STORE4:
    case A_RTC_CNTL_STORE5:
    case A_RTC_CNTL_STORE6:
    case A_RTC_CNTL_STORE7:
        r = s->scratch_reg[(addr - A_RTC_CNTL_STORE4) / 4 + 4];
        break;
    }
    return r;
}

static void esp32_rtc_cntl_write(void *opaque, hwaddr addr, uint64_t value,
                                 unsigned int size)
{
    Esp32RtcCntlState *s = ESP32_RTC_CNTL(opaque);
    switch (addr) {
    case A_RTC_CNTL_OPTIONS0:
        if (value & R_RTC_CNTL_OPTIONS0_SW_SYS_RESET_MASK) {
            s->reset_cause[0] = ESP32_SW_SYS_RESET;
            s->reset_cause[1] = ESP32_SW_SYS_RESET;
            qemu_irq_pulse(s->dig_reset_req);
            value &= ~(R_RTC_CNTL_OPTIONS0_SW_SYS_RESET_MASK);
        }
        if (value & R_RTC_CNTL_OPTIONS0_SW_APPCPU_RESET_MASK) {
            s->reset_cause[1] = ESP32_SW_CPU_RESET;
            qemu_irq_pulse(s->cpu_reset_req[1]);
            value &= ~(R_RTC_CNTL_OPTIONS0_SW_APPCPU_RESET_MASK);
        }
        if (value & R_RTC_CNTL_OPTIONS0_SW_PROCPU_RESET_MASK) {
            s->reset_cause[0] = ESP32_SW_CPU_RESET;
            qemu_irq_pulse(s->cpu_reset_req[0]);
            value &= ~(R_RTC_CNTL_OPTIONS0_SW_PROCPU_RESET_MASK);
        }
        s->options0_reg = value;
        esp32_rtc_update_cpu_stall(s);
        break;

    case A_RTC_CNTL_TIME_UPDATE:
        if (value & R_RTC_CNTL_TIME_UPDATE_UPDATE_MASK) {
            s->time_reg = muldiv64(
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->time_base_ns,
                s->rtc_slowclk_freq, NANOSECONDS_PER_SECOND);
        }
        break;

    case A_RTC_CNTL_RESET_STATE:
        s->stat_vector_sel[0] = FIELD_EX32(value, RTC_CNTL_RESET_STATE,
                                           PROCPU_STAT_VECTOR_SEL);
        s->stat_vector_sel[1] = FIELD_EX32(value, RTC_CNTL_RESET_STATE,
                                           APPCPU_STAT_VECTOR_SEL);
        break;

    case A_RTC_CNTL_STORE0:
    case A_RTC_CNTL_STORE1:
    case A_RTC_CNTL_STORE2:
    case A_RTC_CNTL_STORE3:
        s->scratch_reg[(addr - A_RTC_CNTL_STORE0) / 4] = value;
        break;

    case A_RTC_CNTL_CLK_CONF:
        s->soc_clk = FIELD_EX32(value, RTC_CNTL_CLK_CONF, SOC_CLK_SEL);
        s->rtc_fastclk = FIELD_EX32(value, RTC_CNTL_CLK_CONF, FAST_CLK_RTC_SEL);
        s->rtc_slowclk = FIELD_EX32(value, RTC_CNTL_CLK_CONF, ANA_CLK_RTC_SEL);
        esp32_rtc_update_clk(s);
        break;

    case A_RTC_CNTL_WDTWPROTECT:
        s->wdtwprotect_reg = value;
        break;

    case A_RTC_CNTL_WDTCONFIG0:
    case A_RTC_CNTL_WDTCONFIG1:
    case A_RTC_CNTL_WDTCONFIG2:
    case A_RTC_CNTL_WDTCONFIG3:
    case A_RTC_CNTL_WDTCONFIG4:
    case A_RTC_CNTL_WDTFEED:
        if (s->wdtwprotect_reg != ESP32_RTC_WDT_WKEY) {
            break;
        }
        switch (addr) {
        case A_RTC_CNTL_WDTCONFIG0: {
            uint32_t old = s->wdtconfig0_reg;
            s->wdtconfig0_reg = value;
            if (!(old & R_RTC_CNTL_WDTCONFIG0_WDT_EN_MASK) &&
                (s->wdtconfig0_reg & R_RTC_CNTL_WDTCONFIG0_WDT_EN_MASK)) {
                uint32_t pc = 0;
                int cpu_index = -1;
                if (current_cpu) {
                    cpu_index = current_cpu->cpu_index;
                    CPUClass *cc = CPU_GET_CLASS(current_cpu);
                    if (cc->get_pc) {
                        pc = (uint32_t)cc->get_pc(current_cpu);
                    }
                }
                qemu_log_mask(LOG_GUEST_ERROR,
                              "RTC_CNTL: RTCWDT enabled cpu=%d pc=0x%08x cfg0=0x%08x stg0=%u hold0=%u\n",
                              cpu_index,
                              pc,
                              s->wdtconfig0_reg,
                              (unsigned)FIELD_EX32(s->wdtconfig0_reg, RTC_CNTL_WDTCONFIG0, WDT_STG0),
                              s->wdtconfig1_reg);
                if (current_cpu && qemu_loglevel_mask(LOG_GUEST_ERROR) &&
                    s->wdtconfig1_reg <= 200000) {
                    cpu_dump_state(current_cpu, stderr, 0);
                    esp32_log_backtrace(current_cpu, 16);
                }
            }
            esp32_rtc_wdt_update(s, true);
            break;
        }
        case A_RTC_CNTL_WDTCONFIG1:
            s->wdtconfig1_reg = value;
            if (s->wdtconfig0_reg & R_RTC_CNTL_WDTCONFIG0_WDT_EN_MASK) {
                uint32_t pc = 0;
                int cpu_index = -1;
                if (current_cpu) {
                    cpu_index = current_cpu->cpu_index;
                    CPUClass *cc = CPU_GET_CLASS(current_cpu);
                    if (cc->get_pc) {
                        pc = (uint32_t)cc->get_pc(current_cpu);
                    }
                }
                qemu_log_mask(LOG_GUEST_ERROR,
                              "RTC_CNTL: RTCWDT hold0 write cpu=%d pc=0x%08x hold0=%u\n",
                              cpu_index,
                              pc,
                              s->wdtconfig1_reg);
            }
            esp32_rtc_wdt_update(s, false);
            break;
        case A_RTC_CNTL_WDTCONFIG2:
            s->wdtconfig2_reg = value;
            esp32_rtc_wdt_update(s, false);
            break;
        case A_RTC_CNTL_WDTCONFIG3:
            s->wdtconfig3_reg = value;
            esp32_rtc_wdt_update(s, false);
            break;
        case A_RTC_CNTL_WDTCONFIG4:
            s->wdtconfig4_reg = value;
            esp32_rtc_wdt_update(s, false);
            break;
        case A_RTC_CNTL_WDTFEED:
            if (value & R_RTC_CNTL_WDTFEED_WDT_FEED_MASK) {
                esp32_rtc_wdt_update(s, true);
            }
            break;
        default:
            break;
        }
        break;

    case A_RTC_CNTL_SW_CPU_STALL:
        s->sw_cpu_stall_reg = value;
        esp32_rtc_update_cpu_stall(s);
        break;

    case A_RTC_CNTL_STORE4:
    case A_RTC_CNTL_STORE5:
    case A_RTC_CNTL_STORE6:
    case A_RTC_CNTL_STORE7:
        s->scratch_reg[(addr - A_RTC_CNTL_STORE4) / 4 + 4] = value;
        break;
    }
}

static uint32_t esp32_rtc_wdt_stage_action(const Esp32RtcCntlState *s, uint32_t stage)
{
    switch (stage) {
    case 0:
        return FIELD_EX32(s->wdtconfig0_reg, RTC_CNTL_WDTCONFIG0, WDT_STG0);
    case 1:
        return FIELD_EX32(s->wdtconfig0_reg, RTC_CNTL_WDTCONFIG0, WDT_STG1);
    case 2:
        return FIELD_EX32(s->wdtconfig0_reg, RTC_CNTL_WDTCONFIG0, WDT_STG2);
    case 3:
    default:
        return FIELD_EX32(s->wdtconfig0_reg, RTC_CNTL_WDTCONFIG0, WDT_STG3);
    }
}

static uint32_t esp32_rtc_wdt_stage_hold(const Esp32RtcCntlState *s, uint32_t stage)
{
    switch (stage) {
    case 0:
        return s->wdtconfig1_reg;
    case 1:
        return s->wdtconfig2_reg;
    case 2:
        return s->wdtconfig3_reg;
    case 3:
    default:
        return s->wdtconfig4_reg;
    }
}

static void esp32_rtc_wdt_update(Esp32RtcCntlState *s, bool reset_stage)
{
    if (reset_stage) {
        s->wdt_stage = 0;
    }

    if (!(s->wdtconfig0_reg & R_RTC_CNTL_WDTCONFIG0_WDT_EN_MASK)) {
        timer_del(&s->wdt_timer);
        s->wdt_stage = 0;
        return;
    }

    uint32_t hold = esp32_rtc_wdt_stage_hold(s, s->wdt_stage);
    if (hold == 0) {
        hold = 1;
    }

    uint32_t freq_hz = s->rtc_slowclk_freq ? s->rtc_slowclk_freq : 150000;
    uint64_t ns = muldiv64((uint64_t)hold, NANOSECONDS_PER_SECOND, freq_hz);
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    timer_mod(&s->wdt_timer, now + ns);
}

static void esp32_rtc_wdt_cb(void *opaque)
{
    Esp32RtcCntlState *s = ESP32_RTC_CNTL(opaque);

    if (!(s->wdtconfig0_reg & R_RTC_CNTL_WDTCONFIG0_WDT_EN_MASK)) {
        return;
    }

    uint32_t action = esp32_rtc_wdt_stage_action(s, s->wdt_stage);
    qemu_log_mask(LOG_GUEST_ERROR,
                  "RTC_CNTL: RTCWDT timeout stage=%u action=%u\n",
                  s->wdt_stage,
                  action);
    switch (action) {
    case RTC_WDT_STG_SEL_INT:
        qemu_irq_pulse(s->irq);
        break;
    case RTC_WDT_STG_SEL_RESET_CPU: {
        bool procpu = FIELD_EX32(s->wdtconfig0_reg, RTC_CNTL_WDTCONFIG0, WDT_PROCPU_RESET_EN);
        bool appcpu = FIELD_EX32(s->wdtconfig0_reg, RTC_CNTL_WDTCONFIG0, WDT_APPCPU_RESET_EN);
        if (!procpu && !appcpu) {
            procpu = true;
            appcpu = true;
        }
        if (procpu) {
            s->reset_cause[0] = ESP32_RTCWDT_CPU_RESET;
            qemu_irq_pulse(s->cpu_reset_req[0]);
        }
        if (appcpu) {
            s->reset_cause[1] = ESP32_RTCWDT_CPU_RESET;
            qemu_irq_pulse(s->cpu_reset_req[1]);
        }
        return;
    }
    case RTC_WDT_STG_SEL_RESET_SYSTEM:
        s->reset_cause[0] = ESP32_RTCWDT_SYS_RESET;
        s->reset_cause[1] = ESP32_RTCWDT_SYS_RESET;
        qemu_irq_pulse(s->dig_reset_req);
        return;
    case RTC_WDT_STG_SEL_RESET_RTC:
        s->reset_cause[0] = ESP32_RTCWDT_RTC_RESET;
        s->reset_cause[1] = ESP32_RTCWDT_RTC_RESET;
        qemu_irq_pulse(s->dig_reset_req);
        return;
    case RTC_WDT_STG_SEL_OFF:
    default:
        break;
    }

    if (s->wdt_stage < 3) {
        s->wdt_stage++;
        esp32_rtc_wdt_update(s, false);
    } else {
        esp32_rtc_wdt_update(s, false);
    }
}

static void esp32_rtc_update_cpu_stall(Esp32RtcCntlState* s)
{
    uint32_t procpu_stall = (FIELD_EX32(s->sw_cpu_stall_reg, RTC_CNTL_SW_CPU_STALL, PROCPU_C1) << 2) |
                            (FIELD_EX32(s->options0_reg, RTC_CNTL_OPTIONS0, SW_STALL_PROCPU_C0));

    uint32_t appcpu_stall = (FIELD_EX32(s->sw_cpu_stall_reg, RTC_CNTL_SW_CPU_STALL, APPCPU_C1) << 2) |
                            (FIELD_EX32(s->options0_reg, RTC_CNTL_OPTIONS0, SW_STALL_APPCPU_C0));

    const uint32_t stall_magic_val = 0x86;

    s->cpu_stall_state[0] = procpu_stall == stall_magic_val;
    s->cpu_stall_state[1] = appcpu_stall == stall_magic_val;

    qemu_set_irq(s->cpu_stall_req[0], s->cpu_stall_state[0]);
    qemu_set_irq(s->cpu_stall_req[1], s->cpu_stall_state[1]);
}

static void esp32_rtc_update_clk(Esp32RtcCntlState* s)
{
    const uint32_t slowclk_freq[] = {150000, 32768, 8000000/256};
    const uint32_t fastclk_freq[] = {s->xtal_apb_freq / 4, 8000000};
    uint32_t slow_sel = s->rtc_slowclk;
    uint32_t fast_sel = s->rtc_fastclk;
    if (slow_sel >= ARRAY_SIZE(slowclk_freq)) {
        slow_sel = 0;
    }
    if (fast_sel >= ARRAY_SIZE(fastclk_freq)) {
        fast_sel = 0;
    }
    s->rtc_slowclk_freq = slowclk_freq[slow_sel];
    s->rtc_fastclk_freq = fastclk_freq[fast_sel];
    qemu_irq_pulse(s->clk_update);
}

static const MemoryRegionOps esp32_rtc_cntl_ops = {
    .read =  esp32_rtc_cntl_read,
    .write = esp32_rtc_cntl_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void esp32_rtc_cntl_reset_hold(Object *obj, ResetType type)
{
    Esp32RtcCntlState *s = ESP32_RTC_CNTL(obj);

    s->time_base_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    timer_del(&s->wdt_timer);
    s->wdt_stage = 0;
    s->wdtwprotect_reg = ESP32_RTC_WDT_WKEY;
    s->wdtconfig0_reg = 0;
    s->wdtconfig1_reg = 128000;
    s->wdtconfig2_reg = 80000;
    s->wdtconfig3_reg = 0xfff;
    s->wdtconfig4_reg = 0xfff;
}

static void esp32_rtc_cntl_realize(DeviceState *dev, Error **errp)
{
}

static void esp32_rtc_cntl_init(Object *obj)
{
    Esp32RtcCntlState *s = ESP32_RTC_CNTL(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &esp32_rtc_cntl_ops, s,
                          TYPE_ESP32_RTC_CNTL, ESP32_RTC_CNTL_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    qdev_init_gpio_out_named(DEVICE(sbd), &s->dig_reset_req, ESP32_RTC_DIG_RESET_GPIO, 1);
    qdev_init_gpio_out_named(DEVICE(sbd), &s->cpu_reset_req[0], ESP32_RTC_CPU_RESET_GPIO, ESP32_CPU_COUNT);
    qdev_init_gpio_out_named(DEVICE(sbd), &s->cpu_stall_req[0], ESP32_RTC_CPU_STALL_GPIO, ESP32_CPU_COUNT);
    qdev_init_gpio_out_named(DEVICE(sbd), &s->clk_update, ESP32_RTC_CLK_UPDATE_GPIO, 1);

    for (int i = 0; i < ESP32_CPU_COUNT; ++i) {
        s->reset_cause[i] = ESP32_POWERON_RESET;
        s->stat_vector_sel[i] = true;
    }

    timer_init_ns(&s->wdt_timer, QEMU_CLOCK_VIRTUAL, esp32_rtc_wdt_cb, s);
    s->wdt_stage = 0;
    s->wdtwprotect_reg = ESP32_RTC_WDT_WKEY;
    s->wdtconfig0_reg = 0;
    s->wdtconfig1_reg = 128000;
    s->wdtconfig2_reg = 80000;
    s->wdtconfig3_reg = 0xfff;
    s->wdtconfig4_reg = 0xfff;

    s->rtc_slowclk = ESP32_SLOW_CLK_RC;
    s->rtc_fastclk = ESP32_FAST_CLK_8M;
    s->soc_clk = ESP32_SOC_CLK_XTAL;
    s->xtal_apb_freq = 40000000;
    s->pll_apb_freq = 80000000;
    esp32_rtc_update_clk(s);
}

static Property esp32_rtc_cntl_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void esp32_rtc_cntl_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    rc->phases.hold = esp32_rtc_cntl_reset_hold;
    dc->realize = esp32_rtc_cntl_realize;
    device_class_set_props(dc, esp32_rtc_cntl_properties);
}

static const TypeInfo esp32_rtc_cntl_info = {
    .name = TYPE_ESP32_RTC_CNTL,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32RtcCntlState),
    .instance_init = esp32_rtc_cntl_init,
    .class_init = esp32_rtc_cntl_class_init
};

static void esp32_rtc_cntl_register_types(void)
{
    type_register_static(&esp32_rtc_cntl_info);
}

type_init(esp32_rtc_cntl_register_types)
