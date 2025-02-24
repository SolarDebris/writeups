/*
 * Virtual LZ4 Device
 *
 * Copyright (c) 2017 Milo Kim <woogyom.kim@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "hw/virtio/virtio.h"
#include "migration/qemu-file-types.h"
#include "qemu/host-utils.h"
#include "qemu/module.h"
#include "sysemu/kvm.h"
#include "sysemu/replay.h"
#include "hw/virtio/virtio-mmio.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "trace.h"
#include "hw/hw.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "qemu/bitops.h"

#define TYPE_VIRT_LZ4DEV          "virt-lz4dev"
#define VIRT_lz4dev(obj)          OBJECT_CHECK(Virtlz4devState, (obj), TYPE_VIRT_LZ4DEV)

/* Register map */
#define LZ4DEV_OFFSET_ID 0x00
#define LZ4DEV_OFFSET_LEN 0x08
#define LZ4DEV_OFFSET_TRIGGER 0x10
#define LZ4DEV_INBUF 0x20

#define REG_ID                 0x0
#define CHIP_ID                0xf001

#define INT_ENABLED            BIT(0)
#define INT_BUFFER_DEQ         BIT(1)

typedef struct {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;
    hwaddr dst;
    hwaddr len;
    char inbuf[4096];

} Virtlz4devState;

extern uint64_t lz4dec_x86_64(void *dst, void *src, void *srcend);
uint64_t lz4_cmd_decompress(Virtlz4devState *s, char *dst);

uint64_t lz4_cmd_decompress(Virtlz4devState *s, char *dst)
{
uint64_t res;

	res = lz4dec_x86_64(dst, s->inbuf, s->inbuf+s->len);
	memcpy(&s->inbuf[0], dst, (res > 4096) ? 4096 : res);
	return res;
}

static uint64_t virt_lz4dev_read(void *opaque, hwaddr offset, unsigned size)
{
	Virtlz4devState *s = (Virtlz4devState *)opaque;
	uint64_t data;

        if ((offset>=0x20) && (((offset-0x20)+size)<4096))
        {
		data = 0;
                memcpy(&data, &s->inbuf[offset-0x20], size);
                return data;
        }

    switch (offset) {
    case LZ4DEV_OFFSET_ID:
        return 0xdeadbeef;
    case LZ4DEV_OFFSET_LEN:
        return s->len;
    default:
        break;
    }
    return 0;
}

static void virt_lz4dev_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
Virtlz4devState *s = (Virtlz4devState *)opaque;
uint64_t data;
char outbuf[4096];

	if ((offset>=0x20) && (((offset-0x20)+size)<0x800))
	{
		data = value;
		memcpy(&s->inbuf[offset-0x20], &data, size);
		return;
	}

    switch (offset) {
    case LZ4DEV_OFFSET_LEN:
		if ((hwaddr)value < 2048)
			s->len = (hwaddr)value;
        break;
    case LZ4DEV_OFFSET_TRIGGER:
		// return decompressed size in s->len
		s->len = (hwaddr)lz4_cmd_decompress(s, outbuf);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps virt_lz4dev_ops = {
    .read = virt_lz4dev_read,
    .write = virt_lz4dev_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void virt_lz4dev_realize(DeviceState *d, Error **errp)
{
    Virtlz4devState *s = VIRT_lz4dev(d);
    SysBusDevice *sbd = SYS_BUS_DEVICE(d);

    memory_region_init_io(&s->iomem, OBJECT(s), &virt_lz4dev_ops, s, TYPE_VIRT_LZ4DEV, 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static void virt_lz4dev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = virt_lz4dev_realize;
}

static const TypeInfo virt_lz4dev_info = {
    .name          = TYPE_VIRT_LZ4DEV,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Virtlz4devState),
    .class_init    = virt_lz4dev_class_init,
};

static void virt_lz4dev_register_types(void)
{
    type_register_static(&virt_lz4dev_info);
}

type_init(virt_lz4dev_register_types)

