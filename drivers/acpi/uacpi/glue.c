#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/lockdep.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/memblock.h>
#include <linux/nmi.h>
#include <linux/acpi.h>
#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/jiffies.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <uacpi/uacpi.h>

static struct workqueue_struct *uacpi_wq;
static struct workqueue_struct *uacpi_notify_wq;

uacpi_status uacpi_kernel_initialize(uacpi_init_level current_init_lvl)
{
	switch (current_init_lvl) {
	case UACPI_INIT_LEVEL_EARLY:
		uacpi_wq = alloc_workqueue("uacpi", 0, 1);
		uacpi_notify_wq = alloc_workqueue("uacpi_notify", 0, 0);
		if (!uacpi_wq || !uacpi_notify_wq)
			return UACPI_STATUS_OUT_OF_MEMORY;
		break;
	default:
		break;
	}

	return UACPI_STATUS_OK;
}

void uacpi_kernel_deinitialize(void)
{
	destroy_workqueue(uacpi_wq);
	destroy_workqueue(uacpi_notify_wq);

	uacpi_wq = NULL;
	uacpi_notify_wq = NULL;
}

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address)
{
	uacpi_phys_addr pa;

	pa = acpi_arch_get_root_pointer();
	if (!pa)
		return UACPI_STATUS_NOT_FOUND;

	*out_rsdp_address = pa;
	return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_read(uacpi_pci_address *address,
				   uacpi_size offset, uacpi_u8 byte_width,
				   uacpi_u64 *value)
{
	int result;
	u32 value32;

	result = raw_pci_read(address->segment, address->bus,
			      PCI_DEVFN(address->device, address->function),
			      offset, byte_width, &value32);
	*value = value32;

	return result ? UACPI_STATUS_INVALID_ARGUMENT : UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write(uacpi_pci_address *address,
				    uacpi_size offset, uacpi_u8 byte_width,
				    uacpi_u64 value)
{
	int result;

	result = raw_pci_write(address->segment, address->bus,
			       PCI_DEVFN(address->device, address->function),
			       offset, byte_width, (u32)value);

	return result ? UACPI_STATUS_INVALID_ARGUMENT : UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, uacpi_size len,
				 uacpi_handle *out_handle)
{
	*out_handle = (uacpi_handle)base;

	return UACPI_STATUS_OK;
}

void uacpi_kernel_io_unmap(uacpi_handle handle)
{
	// noop
}

uacpi_status uacpi_kernel_io_read(uacpi_handle handle, uacpi_size offset,
				  uacpi_u8 byte_width, uacpi_u64 *value)
{
	switch (byte_width) {
	case 1:
		*value = inb((u16)(u64)handle + offset);
		break;
	case 2:
		*value = inw((u16)(u64)handle + offset);
		break;
	case 4:
		*value = inl((u16)(u64)handle + offset);
		break;
	default:
		return UACPI_STATUS_INVALID_ARGUMENT;
	}

	return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write(uacpi_handle handle, uacpi_size offset,
				   uacpi_u8 byte_width, uacpi_u64 value)
{
	switch (byte_width) {
	case 1:
		outb(value, (u16)(u64)handle + offset);
		break;
	case 2:
		outw(value, (u16)(u64)handle + offset);
		break;
	case 4:
		outl(value, (u16)(u64)handle + offset);
		break;
	default:
		return UACPI_STATUS_INVALID_ARGUMENT;
	}

	return UACPI_STATUS_OK;
}

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len)
{
	u64 pfn;

	pfn = addr >> PAGE_SHIFT;
	if (page_is_ram(pfn)) {
		if (len > PAGE_SIZE)
			return NULL;
		return (void __iomem __force *)kmap(pfn_to_page(pfn));
	}

	return ioremap_cache(addr, len);
}

void uacpi_kernel_unmap(void *addr, uacpi_size len)
{
	struct page *page;

	page = kmap_to_page(addr);
	if (page)
		kunmap(page);
	else
		iounmap(addr);
}

void *uacpi_kernel_alloc(uacpi_size size)
{
	return kmalloc(size, GFP_KERNEL);
}

void *uacpi_kernel_calloc(uacpi_size count, uacpi_size size)
{
	return kzalloc(count * size, GFP_KERNEL);
}

void uacpi_kernel_free(void *mem)
{
	kfree(mem);
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *format, ...)
{
	va_list args;

	va_start(args, format);
	vprintk(format, args);
	va_end(args);
}

void uacpi_kernel_vlog(uacpi_log_level level, const uacpi_char *format,
		       uacpi_va_list args)
{
	vprintk(format, args);
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void)
{
	return rdtsc();
}

void uacpi_kernel_stall(uacpi_u8 usec)
{
	while (usec) {
		u32 delay = 1000;

		if (delay > usec)
			delay = usec;
		udelay(delay);
		touch_nmi_watchdog();
		usec -= delay;
	}
}

void uacpi_kernel_sleep(uacpi_u64 msec)
{
	msleep(msec);
}

uacpi_handle uacpi_kernel_create_mutex(void)
{
	struct semaphore *sem;

	sem = kmalloc(sizeof(*sem), GFP_KERNEL);
	if (!sem)
		return UACPI_NULL;

	sema_init(sem, 1);
	return sem;
}

void uacpi_kernel_free_mutex(uacpi_handle handle)
{
	struct semaphore *sem;

	sem = (struct semaphore *)handle;
	BUG_ON(!list_empty(&sem->wait_list));
	kfree(sem);
}

uacpi_handle uacpi_kernel_create_event(void)
{
	struct semaphore *sem;

	sem = kmalloc(sizeof(*sem), GFP_KERNEL);
	if (!sem)
		return UACPI_NULL;

	sema_init(sem, 0);
	return sem;
}

void uacpi_kernel_free_event(uacpi_handle handle)
{
	struct semaphore *sem;

	sem = (struct semaphore *)handle;
	BUG_ON(!list_empty(&sem->wait_list));
	kfree(sem);
}

uacpi_thread_id uacpi_kernel_get_thread_id(void)
{
	return (uacpi_thread_id)current;
}

uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle handle, uacpi_u16 timeout)
{
	struct semaphore *sem;
	long jiffies;
	int ret;

	sem = (struct semaphore *)handle;
	if (!timeout) {
		ret = down_trylock(sem);
		return ret ? UACPI_STATUS_TIMEOUT : UACPI_STATUS_OK;
	}

	if (timeout == 0xffff)
		jiffies = MAX_SCHEDULE_TIMEOUT;
	else
		jiffies = msecs_to_jiffies(timeout);

	ret = down_timeout(sem, jiffies);
	return ret ? UACPI_STATUS_TIMEOUT : UACPI_STATUS_OK;
}

void uacpi_kernel_release_mutex(uacpi_handle handle)
{
	struct semaphore *sem;

	// i trust you to not release a mutex you don't own...
	sem = (struct semaphore *)handle;
	up(sem);
}

uacpi_bool uacpi_kernel_wait_for_event(uacpi_handle handle, uacpi_u16 timeout)
{
	struct semaphore *sem;
	long jiffies;
	int ret;

	sem = (struct semaphore *)handle;
	if (!timeout) {
		ret = down_trylock(sem);
		return ret ? UACPI_FALSE : UACPI_TRUE;
	}

	if (timeout == 0xffff)
		jiffies = MAX_SCHEDULE_TIMEOUT;
	else
		jiffies = msecs_to_jiffies(timeout);

	ret = down_timeout(sem, jiffies);
	return ret ? UACPI_FALSE : UACPI_TRUE;
}

void uacpi_kernel_signal_event(uacpi_handle handle)
{
	struct semaphore *sem;

	sem = (struct semaphore *)handle;
	up(sem);
}

void uacpi_kernel_reset_event(uacpi_handle handle)
{
	struct semaphore *sem;

	sem = (struct semaphore *)handle;
	while (down_trylock(sem) == 0)
		;
}

uacpi_status
uacpi_kernel_handle_firmware_request(uacpi_firmware_request *request)
{
	switch (request->type) {
	case UACPI_FIRMWARE_REQUEST_TYPE_BREAKPOINT:
		pr_err("Breakpoint opcode executed\n");
		break;
	case UACPI_FIRMWARE_REQUEST_TYPE_FATAL:
		pr_err("Fatal opcode executed\n");
		break;
	}

	return UACPI_STATUS_OK;
}

static u32 uacpi_sci_irq = 0;
static uacpi_interrupt_handler uacpi_irq_handler;
static void *uacpi_irq_context;

static irqreturn_t uacpi_irq(int irq, void *dev_id)
{
	if ((*uacpi_irq_handler)(uacpi_irq_context) == UACPI_INTERRUPT_HANDLED)
		return IRQ_HANDLED;

	return IRQ_NONE;
}

uacpi_status uacpi_kernel_install_interrupt_handler(
	uacpi_u32 gsi, uacpi_interrupt_handler handler, uacpi_handle ctx,
	uacpi_handle *out_irq_handle)
{
	u32 irq;

	if (acpi_gsi_to_irq(gsi, &irq) < 0)
		return UACPI_STATUS_INVALID_ARGUMENT;

	uacpi_irq_handler = handler;
	uacpi_irq_context = ctx;
	if (request_threaded_irq(irq, NULL, uacpi_irq,
				 IRQF_SHARED | IRQF_ONESHOT, "uacpi",
				 uacpi_irq)) {
		uacpi_irq_handler = NULL;
		return UACPI_STATUS_INTERNAL_ERROR;
	}

	uacpi_sci_irq = irq;

	return UACPI_STATUS_OK;
}

uacpi_status
uacpi_kernel_uninstall_interrupt_handler(uacpi_interrupt_handler handler,
					 uacpi_handle irq_handle)
{
	if (!uacpi_sci_irq)
		return UACPI_STATUS_INVALID_ARGUMENT;

	free_irq(uacpi_sci_irq, uacpi_irq);
	uacpi_irq_handler = NULL;
	uacpi_irq_context = NULL;
	uacpi_sci_irq = 0;

	return UACPI_STATUS_OK;
}

uacpi_handle uacpi_kernel_create_spinlock(void)
{
	struct raw_spinlock *lock;

	lock = kmalloc(sizeof(*lock), GFP_KERNEL);
	if (!lock)
		return UACPI_NULL;

	raw_spin_lock_init(lock);
	return lock;
}

void uacpi_kernel_free_spinlock(uacpi_handle handle)
{
	struct raw_spinlock *lock;

	lock = (struct raw_spinlock *)handle;
	BUG_ON(raw_spin_is_locked(lock));
	kfree(lock);
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle handle)
{
	struct raw_spinlock *lock;
	unsigned long flags;

	lock = (struct raw_spinlock *)handle;
	raw_spin_lock_irqsave(lock, flags);
	return flags;
}

void uacpi_kernel_unlock_spinlock(uacpi_handle handle, uacpi_cpu_flags flags)
{
	struct raw_spinlock *lock;

	lock = (struct raw_spinlock *)handle;
	raw_spin_unlock_irqrestore(lock, flags);
}

struct uacpi_work {
	struct work_struct work;
	uacpi_work_handler handler;
	uacpi_handle ctx;
};

static void acpi_work_fn(struct work_struct *work)
{
	struct uacpi_work *uwork;

	uwork = container_of(work, struct uacpi_work, work);
	uwork->handler(uwork->ctx);
	kfree(uwork);
}

uacpi_status uacpi_kernel_schedule_work(uacpi_work_type type,
					uacpi_work_handler handler,
					uacpi_handle ctx)
{
	struct uacpi_work *work;
	int ret;

	work = kmalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return UACPI_STATUS_OUT_OF_MEMORY;

	INIT_WORK(&work->work, acpi_work_fn);
	work->handler = handler;
	work->ctx = ctx;

	switch (type) {
	case UACPI_WORK_GPE_EXECUTION:
		ret = queue_work_on(0, uacpi_wq, &work->work);
		break;
	case UACPI_WORK_NOTIFICATION:
		ret = queue_work(uacpi_notify_wq, &work->work);
		break;
	}

	return ret ? UACPI_STATUS_OK : UACPI_STATUS_INTERNAL_ERROR;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void)
{
	flush_workqueue(uacpi_wq);
	flush_workqueue(uacpi_notify_wq);

	return UACPI_STATUS_OK;
}
