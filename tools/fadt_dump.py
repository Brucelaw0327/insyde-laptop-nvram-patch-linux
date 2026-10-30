import struct
import sys

b = open("/sys/firmware/acpi/tables/FACP", "rb").read()
n = len(b)
print("长度 %d  签名 %r  版本 %d  OEM %r" % (n, b[:4], b[8], b[10:16]))
print("校验和: %s (sum=%#x)" % ("通过" if (sum(b) & 0xFF) == 0 else "不通过", sum(b) & 0xFF))
print()

FIELDS = [
    (0x00, 4, "Signature"),
    (0x04, 4, "Length"),
    (0x08, 1, "Revision"),
    (0x09, 1, "Checksum"),
    (0x0A, 6, "OEMID"),
    (0x10, 8, "OEM Table ID"),
    (0x18, 4, "OEM Revision"),
    (0x1C, 4, "Creator ID"),
    (0x20, 4, "Creator Revision"),
    (0x24, 4, "FIRMWARE_CTRL (FACS, 32-bit)"),
    (0x28, 4, "DSDT"),
    (0x2C, 4, "Reserved"),
    (0x30, 2, "SMI_CMD"),
    (0x34, 4, "PM1a_EVT_BLK"),
    (0x38, 4, "PM1b_EVT_BLK"),
    (0x3C, 4, "PM1a_CNT_BLK"),
    (0x40, 4, "PM1b_CNT_BLK"),
    (0x44, 4, "PM2_CNT_BLK"),
    (0x48, 4, "PM_TMR_BLK"),
    (0x4C, 4, "GPE0_BLK"),
    (0x50, 4, "GPE1_BLK"),
    (0x54, 1, "PM1_EVT_LEN"),
    (0x55, 1, "PM1_CNT_LEN"),
    (0x56, 1, "PM2_CNT_LEN"),
    (0x57, 1, "PM_TMR_LEN"),
    (0x58, 1, "GPE0_BLK_LEN"),
    (0x59, 1, "GPE1_BLK_LEN"),
    (0x5A, 1, "GPE1_BASE"),
    (0x5B, 1, "CST_CNT"),
    (0x5C, 2, "P_LVL2_LAT"),
    (0x5E, 2, "P_LVL3_LAT"),
    (0x60, 2, "FLUSH_SIZE"),
    (0x62, 2, "FLUSH_STRIDE"),
    (0x64, 1, "DUTY_OFFSET"),
    (0x65, 1, "DUTY_WIDTH"),
    (0x66, 1, "DAY_ALRM"),
    (0x67, 1, "MON_ALRM"),
    (0x68, 1, "CENTURY"),
    (0x69, 2, "IA_PC_BOOT_ARCH"),
    (0x6B, 3, "Reserved"),
    (0x6E, 1, "FADT Minor Version"),
    (0x70, 4, "Flags (32-bit)"),
    (0x74, 12, "RESET_REG (GAS)"),
    (0x80, 1, "RESET_VALUE"),
    (0x84, 8, "X_FIRMWARE_CTRL (X_FACS, 64-bit)"),
    (0x8C, 8, "X_DSDT"),
    (0x94, 12, "X_PM1a_EVT_BLK"),
    (0xA0, 12, "X_PM1b_EVT_BLK"),
    (0xAC, 12, "X_PM1a_CNT_BLK"),
    (0xB8, 12, "X_PM1b_CNT_BLK"),
    (0xC4, 12, "X_PM2_CNT_BLK"),
    (0xD0, 12, "X_PM_TMR_BLK"),
    (0xDC, 12, "X_GPE0_BLK"),
    (0xE8, 12, "X_GPE1_BLK"),
    (0xF4, 12, "SLEEP_CONTROL_REG"),
    (0x100, 12, "SLEEP_STATUS_REG"),
    (0x10C, 8, "HYPERVISOR_VENDOR_ID"),
]

for off, ln, name in FIELDS:
    if off + ln > n:
        continue
    raw = b[off:off + ln]
    if ln == 1:
        val = "%#04x (%d)" % (raw[0], raw[0])
    elif ln == 2:
        v = struct.unpack("<H", raw)[0]
        val = "%#06x (%d)" % (v, v)
    elif ln == 4:
        v = struct.unpack("<I", raw)[0]
        val = "%#010x (%d)" % (v, v)
    elif ln == 8:
        v = struct.unpack("<Q", raw)[0]
        val = "%#018x (%d)" % (v, v)
    else:
        val = raw.hex(" ")
    print("  +%#05x  %-32s  %s" % (off, name, val))

print()
flags = struct.unpack_from("<I", b, 0x70)[0]
print("flags=%#010x 逐位：" % flags)
BITS = [
    (0, "WBINVD"), (1, "WBINVD_FLUSH"), (2, "PROC_C1"), (3, "P_LVL2_UP"),
    (4, "PWR_BUTTON"), (5, "SLEEP_BUTTON"), (6, "FIX_RTC"), (7, "RTC_S4"),
    (8, "TMR_VAL_EXT"), (9, "DCK_CAP"), (10, "RESET_REG_SUP"),
    (11, "SEALED_CASE"), (12, "HEADLESS"), (13, "CPU_SW_SLP"),
    (14, "PCI_EXP_WAK"), (15, "USE_PLATFORM_CLOCK"),
    (16, "S4_RTC_STS_VALID"), (17, "REMOTE_POWER_ON_CAPABLE"),
    (18, "FORCE_APIC_CLUSTER_MODEL"), (19, "FORCE_APIC_PHYSICAL_DESTINATION_MODE"),
    (20, "HW_REDUCED_ACPI"), (21, "LOW_POWER_S0_IDLE_CAPABLE"),
]
for bit, name in BITS:
    if flags & (1 << bit):
        print("  bit %2d  %s  = 1" % (bit, name))
print()
print("bit 22..31 =", [i for i in range(22, 32) if flags & (1 << i)], "（规范定义为 0）")
