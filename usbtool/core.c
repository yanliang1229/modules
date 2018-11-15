#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#include "common.h"
#include "libusb.h"

const struct usb_os_backend * const usb_backend = &linux_usbfs_backend;
const struct libusb_version libusb_version_internal = {
	LIBUSB_MAJOR, LIBUSB_MINOR, LIBUSB_MICRO, LIBUSB_NANO, LIBUSB_RC,
};

struct libusb_context *usb_default_context = NULL;
static int default_context_refcnt = 0;
static usb_mutex_static_t default_context_lock = USBI_MUTEX_INITIALIZER;

#define DISCOVERED_DEVICES_SIZE_STEP 8

static struct discovered_devs *discovered_devs_alloc(void)
{
	struct discovered_devs *ret =
		malloc(sizeof(*ret) + (sizeof(void *) * DISCOVERED_DEVICES_SIZE_STEP));

	if (ret) {
		ret->len = 0;
		ret->capacity = DISCOVERED_DEVICES_SIZE_STEP;
	}
	return ret;
}

struct discovered_devs *discovered_devs_append(
	struct discovered_devs *discdevs, struct libusb_device *dev)
{
	size_t len = discdevs->len;
	size_t capacity;

	if (len < discdevs->capacity) {
		discdevs->devices[len] = libusb_ref_device(dev);
		discdevs->len++;
		return discdevs;
	}

	usb_dbg("need to increase capacity");
	capacity = discdevs->capacity + DISCOVERED_DEVICES_SIZE_STEP;
	discdevs = realloc(discdevs,
		sizeof(*discdevs) + (sizeof(void *) * capacity));
	if (discdevs) {
		discdevs->capacity = capacity;
		discdevs->devices[len] = libusb_ref_device(dev);
		discdevs->len++;
	}

	return discdevs;
}

static void discovered_devs_free(struct discovered_devs *discdevs)
{
	size_t i;

	for (i = 0; i < discdevs->len; i++)
		libusb_unref_device(discdevs->devices[i]);

	free(discdevs);
}

struct libusb_device *usb_alloc_device(struct libusb_context *ctx,
	unsigned long session_id)
{
	size_t priv_size = usb_backend->device_priv_size;
	struct libusb_device *dev = calloc(1, sizeof(*dev) + priv_size);
	int r;

	if (!dev)
		return NULL;

	r = usb_mutex_init(&dev->lock, NULL);
	if (r) {
		free(dev);
		return NULL;
	}

	dev->ctx = ctx;
	dev->refcnt = 1;
	dev->session_data = session_id;
	dev->speed = LIBUSB_SPEED_UNKNOWN;
	memset(&dev->os_priv, 0, priv_size);

	usb_mutex_lock(&ctx->usb_devs_lock);
	list_add(&dev->list, &ctx->usb_devs);
	usb_mutex_unlock(&ctx->usb_devs_lock);
	return dev;
}

int usb_sanitize_device(struct libusb_device *dev)
{
	int r;
	unsigned char raw_desc[DEVICE_DESC_LENGTH];
	uint8_t num_configurations;
	int host_endian;

	r = usb_backend->get_device_descriptor(dev, raw_desc, &host_endian);
	if (r < 0)
		return r;

	num_configurations = raw_desc[DEVICE_DESC_LENGTH - 1];
	if (num_configurations > USB_MAXCONFIG) {
		usb_err(DEVICE_CTX(dev), "too many configurations");
		return LIBUSB_ERROR_IO;
	} else if (num_configurations == 0)
		usb_dbg("zero configurations, maybe an unauthorized device");

	dev->num_configurations = num_configurations;
	return 0;
}

struct libusb_device *usb_get_device_by_session_id(struct libusb_context *ctx,
	unsigned long session_id)
{
	struct libusb_device *dev;
	struct libusb_device *ret = NULL;

	usb_mutex_lock(&ctx->usb_devs_lock);
	list_for_each_entry(dev, &ctx->usb_devs, list, struct libusb_device)
		if (dev->session_data == session_id) {
			ret = dev;
			break;
		}
	usb_mutex_unlock(&ctx->usb_devs_lock);

	return ret;
}

ssize_t libusb_get_device_list(libusb_context *ctx,
	libusb_device ***list)
{
	struct discovered_devs *discdevs = discovered_devs_alloc();
	struct libusb_device **ret;
	int r = 0;
	ssize_t i, len;
	USBI_GET_CONTEXT(ctx);
	usb_dbg("");

	if (!discdevs)
		return LIBUSB_ERROR_NO_MEM;

	r = usb_backend->get_device_list(ctx, &discdevs);
	if (r < 0) {
		len = r;
		goto out;
	}

	/* convert discovered_devs into a list */
	len = discdevs->len;
	ret = malloc(sizeof(void *) * (len + 1));
	if (!ret) {
		len = LIBUSB_ERROR_NO_MEM;
		goto out;
	}

	memset(ret, 0, sizeof(void *) * (len + 1));
	for (i = 0; i < len; i++) {
		struct libusb_device *dev = discdevs->devices[i];
		ret[i] = libusb_ref_device(dev);
	}
	*list = ret;

out:
	discovered_devs_free(discdevs);
	return len;
}

void libusb_free_device_list(libusb_device **list,
	int unref_devices)
{
	if (!list)
		return;

	if (unref_devices) {
		int i = 0;
		struct libusb_device *dev;

		while ((dev = list[i++]) != NULL)
			libusb_unref_device(dev);
	}
	free(list);
}

uint8_t libusb_get_bus_number(libusb_device *dev)
{
	return dev->bus_number;
}

uint8_t libusb_get_device_address(libusb_device *dev)
{
	return dev->device_address;
}

int  libusb_get_device_speed(libusb_device *dev)
{
	return dev->speed;
}

static struct libusb_endpoint_descriptor *find_endpoint(
	struct libusb_config_descriptor *config, unsigned char endpoint)
{
	int iface_idx;
	for (iface_idx = 0; iface_idx < config->bNumInterfaces; iface_idx++) {
		 struct libusb_interface *iface = &config->interface[iface_idx];
		int altsetting_idx;

		for (altsetting_idx = 0; altsetting_idx < iface->num_altsetting;
				altsetting_idx++) {
			struct libusb_interface_descriptor *altsetting
				= &iface->altsetting[altsetting_idx];
			int ep_idx;

			for (ep_idx = 0; ep_idx < altsetting->bNumEndpoints; ep_idx++) {
				 struct libusb_endpoint_descriptor *ep =
					&altsetting->endpoint[ep_idx];
				if (ep->bEndpointAddress == endpoint)
					return ep;
			}
		}
	}
	return NULL;
}

static struct libusb_endpoint_descriptor *libusb_get_endpoint_descriptor(
		libusb_device *dev,
		unsigned char endpoint
)
{
	struct libusb_config_descriptor *config;
	struct libusb_endpoint_descriptor *ep;
	int r;

	r = libusb_get_active_config_descriptor(dev, &config);
	if (r < 0) {
		usb_err(DEVICE_CTX(dev),
			"could not retrieve active config descriptor");
		return NULL;
	}

	ep = find_endpoint(config, endpoint);
	if (!ep)
		return NULL;
	libusb_free_config_descriptor(config);
	return ep;
	
}

int  libusb_get_max_packet_size(libusb_device *dev,
	unsigned char endpoint)
{
	struct libusb_endpoint_descriptor *ep = NULL;
	int r = 0;

	ep = libusb_get_endpoint_descriptor(dev, endpoint);
	if (ep)
		r= ep->wMaxPacketSize;
	else
		r = LIBUSB_ERROR_NOT_FOUND;
	return r;
}

int  libusb_get_endpoint_type(libusb_device *dev,
	unsigned char endpoint)
{
	struct libusb_endpoint_descriptor *ep = NULL;
	int r = 0;

	ep = libusb_get_endpoint_descriptor(dev, endpoint);
	if (ep)
		r= ep->bDescriptorType;
	else
		r = LIBUSB_ERROR_NOT_FOUND;
	return r;
}

int  libusb_get_max_iso_packet_size(libusb_device *dev,
	unsigned char endpoint)
{
	enum libusb_transfer_type ep_type;
	uint16_t val;
	int r;
	struct libusb_endpoint_descriptor *ep = NULL;

	ep = libusb_get_endpoint_descriptor(dev, endpoint);
	if (ep)
		r= ep->bDescriptorType;
	else
		return LIBUSB_ERROR_NOT_FOUND;

	val = ep->wMaxPacketSize;
	ep_type = ep->bmAttributes & 0x3;

	r = val & 0x07ff;
	if (ep_type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS
			|| ep_type == LIBUSB_TRANSFER_TYPE_INTERRUPT)
		r *= (1 + ((val >> 11) & 3));
	return r;
}

libusb_device *libusb_ref_device(libusb_device *dev)
{
	usb_mutex_lock(&dev->lock);
	dev->refcnt++;
	usb_mutex_unlock(&dev->lock);
	return dev;
}

void libusb_unref_device(libusb_device *dev)
{
	int refcnt;

	if (!dev)
		return;

	usb_mutex_lock(&dev->lock);
	refcnt = --dev->refcnt;
	usb_mutex_unlock(&dev->lock);

	if (refcnt == 0) {
		usb_dbg("destroy device %d.%d", dev->bus_number, dev->device_address);

		if (usb_backend->destroy_device)
			usb_backend->destroy_device(dev);

		usb_mutex_lock(&dev->ctx->usb_devs_lock);
		list_del(&dev->list);
		usb_mutex_unlock(&dev->ctx->usb_devs_lock);

		usb_mutex_destroy(&dev->lock);
		free(dev);
	}
}

void usb_fd_notification(struct libusb_context *ctx)
{
	unsigned char dummy = 1;
	ssize_t r;

	if (ctx == NULL)
		return;

	/* record that we are messing with poll fds */
	usb_mutex_lock(&ctx->pollfd_modify_lock);
	ctx->pollfd_modify++;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);

	/* write some data on control pipe to interrupt event handlers */
	r = usb_write(ctx->ctrl_pipe[1], &dummy, sizeof(dummy));
	if (r <= 0) {
		usb_warn(ctx, "internal signalling write failed");
		usb_mutex_lock(&ctx->pollfd_modify_lock);
		ctx->pollfd_modify--;
		usb_mutex_unlock(&ctx->pollfd_modify_lock);
		return;
	}

	/* take event handling lock */
	libusb_lock_events(ctx);

	/* read the dummy data */
	r = usb_read(ctx->ctrl_pipe[0], &dummy, sizeof(dummy));
	if (r <= 0)
		usb_warn(ctx, "internal signalling read failed");

	/* we're done with modifying poll fds */
	usb_mutex_lock(&ctx->pollfd_modify_lock);
	ctx->pollfd_modify--;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);

	/* Release event handling lock and wake up event waiters */
	libusb_unlock_events(ctx);
}

int  libusb_open(libusb_device *dev, libusb_device_handle **handle)
{
	struct libusb_context *ctx = DEVICE_CTX(dev);
	struct libusb_device_handle *_handle;
	size_t priv_size = usb_backend->device_handle_priv_size;
	int r;
	usb_dbg("open %d.%d", dev->bus_number, dev->device_address);

	_handle = malloc(sizeof(*_handle) + priv_size);
	if (!_handle)
		return LIBUSB_ERROR_NO_MEM;

	r = usb_mutex_init(&_handle->lock, NULL);
	if (r) {
		free(_handle);
		return LIBUSB_ERROR_OTHER;
	}

	_handle->dev = libusb_ref_device(dev);
	_handle->claimed_interfaces = 0;
	memset(&_handle->os_priv, 0, priv_size);

	r = usb_backend->open(_handle);
	if (r < 0) {
		usb_dbg("open %d.%d returns %d", dev->bus_number, dev->device_address, r);
		libusb_unref_device(dev);
		usb_mutex_destroy(&_handle->lock);
		free(_handle);
		return r;
	}

	usb_mutex_lock(&ctx->open_devs_lock);
	list_add(&_handle->list, &ctx->open_devs);
	usb_mutex_unlock(&ctx->open_devs_lock);
	*handle = _handle;

	usb_fd_notification(ctx);

	return 0;
}

libusb_device_handle *_libusb_open_device_with_vid_pid(
	libusb_context *ctx, uint16_t vendor_id, uint16_t product_id)
{
	struct libusb_device **devs;
	struct libusb_device *found = NULL;
	struct libusb_device *dev;
	struct libusb_device_handle *handle = NULL;
	size_t i = 0;
	int r;

	if (libusb_get_device_list(ctx, &devs) < 0)
		return NULL;

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0)
			goto out;
		if (desc.idVendor == vendor_id && desc.idProduct == product_id) {
			found = dev;
			break;
		}
	}

	if (found) {
		r = libusb_open(found, &handle);
		if (r < 0)
			handle = NULL;
	}

out:
	libusb_free_device_list(devs, 1);
	return handle;
}

static void do_close(struct libusb_context *ctx,
	struct libusb_device_handle *dev_handle)
{
	struct usb_transfer *itransfer;
	struct usb_transfer *tmp;

	libusb_lock_events(ctx);

	/* remove any transfers in flight that are for this device */
	usb_mutex_lock(&ctx->flying_transfers_lock);

	/* safe iteration because transfers may be being deleted */
	list_for_each_entry_safe(itransfer, tmp, 
			&ctx->flying_transfers, list, struct usb_transfer) {
		struct libusb_transfer *transfer =
		        USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

		if (transfer->dev_handle != dev_handle)
			continue;

		if (!(itransfer->flags & USBI_TRANSFER_DEVICE_DISAPPEARED)) {
			usb_err(ctx, "Device handle closed while transfer was still being processed,\
					but the device is still connected as far as we know");

			if (itransfer->flags & USBI_TRANSFER_CANCELLING)
				usb_warn(ctx, "A cancellation for an in-flight transfer hasn't completed\
						but closing the device handle");
			else
				usb_err(ctx, "A cancellation hasn't even been scheduled on the transfer \
						for which the device is closing");
		}

		/* remove from the list of in-flight transfers and make sure
		 * we don't accidentally use the device handle in the future
		 * (or that such accesses will be easily caught and identified as a crash)
		 */
		usb_mutex_lock(&itransfer->lock);
		list_del(&itransfer->list);
		transfer->dev_handle = NULL;
		usb_mutex_unlock(&itransfer->lock);

		/* it is up to the user to free up the actual transfer struct.  this is
		 * just making sure that we don't attempt to process the transfer after
		 * the device handle is invalid
		 */
		usb_dbg("Removed transfer %p from the in-flight list because device handle %p closed",
			 transfer, dev_handle);
	}
	usb_mutex_unlock(&ctx->flying_transfers_lock);

	libusb_unlock_events(ctx);

	usb_mutex_lock(&ctx->open_devs_lock);
	list_del(&dev_handle->list);
	usb_mutex_unlock(&ctx->open_devs_lock);

	usb_backend->close(dev_handle);
	libusb_unref_device(dev_handle->dev);
	usb_mutex_destroy(&dev_handle->lock);
	free(dev_handle);
}

void libusb_close(libusb_device_handle *dev_handle)
{
	struct libusb_context *ctx;
	unsigned char dummy = 1;
	ssize_t r;

	if (!dev_handle)
		return;
	usb_dbg("");

	ctx = HANDLE_CTX(dev_handle);

	usb_mutex_lock(&ctx->pollfd_modify_lock);
	ctx->pollfd_modify++;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);

	/* write some data on control pipe to interrupt event handlers */
	r = usb_write(ctx->ctrl_pipe[1], &dummy, sizeof(dummy));
	if (r <= 0) {
		usb_warn(ctx, "internal signalling write failed, closing anyway");
		do_close(ctx, dev_handle);
		usb_mutex_lock(&ctx->pollfd_modify_lock);
		ctx->pollfd_modify--;
		usb_mutex_unlock(&ctx->pollfd_modify_lock);
		return;
	}

	/* take event handling lock */
	libusb_lock_events(ctx);

	/* read the dummy data */
	r = usb_read(ctx->ctrl_pipe[0], &dummy, sizeof(dummy));
	if (r <= 0)
		usb_warn(ctx, "internal signalling read failed, closing anyway");

	/* Close the device */
	do_close(ctx, dev_handle);

	/* we're done with modifying poll fds */
	usb_mutex_lock(&ctx->pollfd_modify_lock);
	ctx->pollfd_modify--;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);

	/* Release event handling lock and wake up event waiters */
	libusb_unlock_events(ctx);
}

libusb_device * libusb_get_device(libusb_device_handle *dev_handle)
{
	return dev_handle->dev;
}

int libusb_get_configuration(libusb_device_handle *dev,
	int *config)
{
	int r = LIBUSB_ERROR_NOT_SUPPORTED;

	usb_dbg("");
	if (usb_backend->get_configuration)
		r = usb_backend->get_configuration(dev, config);

	if (r == LIBUSB_ERROR_NOT_SUPPORTED) {
		uint8_t tmp = 0;
		usb_dbg("falling back to control message");
		r = libusb_control_transfer(dev, LIBUSB_ENDPOINT_IN,
			LIBUSB_REQUEST_GET_CONFIGURATION, 0, 0, &tmp, 1, 1000);
		if (r == 0) {
			usb_err(HANDLE_CTX(dev), "zero bytes returned in ctrl transfer?");
			r = LIBUSB_ERROR_IO;
		} else if (r == 1) {
			r = 0;
			*config = tmp;
		} else {
			usb_dbg("control failed, error %d", r);
		}
	}

	if (r == 0)
		usb_dbg("active config %d", *config);

	return r;
}

int  libusb_set_configuration(libusb_device_handle *dev,
	int configuration)
{
	usb_dbg("configuration %d", configuration);
	return usb_backend->set_configuration(dev, configuration);
}

int  libusb_claim_interface(libusb_device_handle *dev,
	int interface_number)
{
	int r = 0;

	usb_dbg("interface %d", interface_number);
	if (interface_number >= USB_MAXINTERFACES)
		return LIBUSB_ERROR_INVALID_PARAM;

	usb_mutex_lock(&dev->lock);
	if (dev->claimed_interfaces & (1 << interface_number))
		goto out;

	r = usb_backend->claim_interface(dev, interface_number);
	if (r == 0)
		dev->claimed_interfaces |= 1 << interface_number;

out:
	usb_mutex_unlock(&dev->lock);
	return r;
}

int  libusb_release_interface(libusb_device_handle *dev,
	int interface_number)
{
	int r;

	usb_dbg("interface %d", interface_number);
	if (interface_number >= USB_MAXINTERFACES)
		return LIBUSB_ERROR_INVALID_PARAM;

	usb_mutex_lock(&dev->lock);
	if (!(dev->claimed_interfaces & (1 << interface_number))) {
		r = LIBUSB_ERROR_NOT_FOUND;
		goto out;
	}

	r = usb_backend->release_interface(dev, interface_number);
	if (r == 0)
		dev->claimed_interfaces &= ~(1 << interface_number);

out:
	usb_mutex_unlock(&dev->lock);
	return r;
}

int  libusb_set_interface_alt_setting(libusb_device_handle *dev,
	int interface_number, int alternate_setting)
{
	usb_dbg("interface %d altsetting %d",
		interface_number, alternate_setting);
	if (interface_number >= USB_MAXINTERFACES)
		return LIBUSB_ERROR_INVALID_PARAM;

	usb_mutex_lock(&dev->lock);
	if (!(dev->claimed_interfaces & (1 << interface_number))) {
		usb_mutex_unlock(&dev->lock);
		return LIBUSB_ERROR_NOT_FOUND;
	}
	usb_mutex_unlock(&dev->lock);

	return usb_backend->set_interface_altsetting(dev, interface_number,
		alternate_setting);
}

int  libusb_clear_halt(libusb_device_handle *dev,
	unsigned char endpoint)
{
	usb_dbg("endpoint %x", endpoint);
	return usb_backend->clear_halt(dev, endpoint);
}

int  libusb_reset_device(libusb_device_handle *dev)
{
	usb_dbg("");
	return usb_backend->reset_device(dev);
}

void libusb_close_device(libusb_device_handle *dev)
{
	usb_backend->close(dev);	
}

int  libusb_kernel_driver_active(libusb_device_handle *dev,
	int interface_number)
{
	usb_dbg("interface %d", interface_number);
	if (usb_backend->kernel_driver_active)
		return usb_backend->kernel_driver_active(dev, interface_number);
	else
		return LIBUSB_ERROR_NOT_SUPPORTED;
}

int  libusb_detach_kernel_driver(libusb_device_handle *dev,
	int interface_number)
{
	usb_dbg("interface %d", interface_number);
	if (usb_backend->detach_kernel_driver)
		return usb_backend->detach_kernel_driver(dev, interface_number);
	else
		return LIBUSB_ERROR_NOT_SUPPORTED;
}

int  libusb_attach_kernel_driver(libusb_device_handle *dev,
	int interface_number)
{
	usb_dbg("interface %d", interface_number);
	if (usb_backend->attach_kernel_driver)
		return usb_backend->attach_kernel_driver(dev, interface_number);
	else
		return LIBUSB_ERROR_NOT_SUPPORTED;
}

void libusb_set_debug(libusb_context *ctx, int level)
{
	USBI_GET_CONTEXT(ctx);
	if (!ctx->debug_fixed)
		ctx->debug = level;
}

int libusb_init(libusb_context **context)
{
	char *dbg = getenv("LIBUSB_DEBUG");
	struct libusb_context *ctx;
	int r = 0;

	usb_mutex_static_lock(&default_context_lock);
	if (!context && usb_default_context) {
		usb_dbg("reusing default context");
		default_context_refcnt++;
		usb_mutex_static_unlock(&default_context_lock);
		return 0;
	}

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		r = LIBUSB_ERROR_NO_MEM;
		goto err_unlock;
	}
	memset(ctx, 0, sizeof(*ctx));

	if (dbg) {
		ctx->debug = atoi(dbg);
		if (ctx->debug)
			ctx->debug_fixed = 1;
	}

	usb_dbg("libusb-%d.%d.%d%s%s%s",
	         libusb_version_internal.major,
	         libusb_version_internal.minor,
	         libusb_version_internal.micro,
	         libusb_version_internal.rc,
	         libusb_version_internal.describe[0] ? " git:" : "",
	         libusb_version_internal.describe);

	if (usb_backend->init) {
		r = usb_backend->init(ctx);
		if (r)
			goto err_free_ctx;
	}

	usb_mutex_init(&ctx->usb_devs_lock, NULL);
	usb_mutex_init(&ctx->open_devs_lock, NULL);
	list_init(&ctx->usb_devs);
	list_init(&ctx->open_devs);

	r = usb_io_init(ctx);
	if (r < 0) {
		if (usb_backend->exit)
			usb_backend->exit();
		goto err_destroy_mutex;
	}

	if (context) {
		*context = ctx;
	} else if (!usb_default_context) {
		usb_dbg("created default context");
		usb_default_context = ctx;
		default_context_refcnt++;
	}
	usb_mutex_static_unlock(&default_context_lock);

	return 0;

err_destroy_mutex:
	usb_mutex_destroy(&ctx->open_devs_lock);
	usb_mutex_destroy(&ctx->usb_devs_lock);
err_free_ctx:
	free(ctx);
err_unlock:
	usb_mutex_static_unlock(&default_context_lock);
	return r;
}

void  libusb_exit(struct libusb_context *ctx)
{
	usb_dbg("");
	USBI_GET_CONTEXT(ctx);

	/* if working with default context, only actually do the deinitialization
	 * if we're the last user */
	if (ctx == usb_default_context) {
		usb_mutex_static_lock(&default_context_lock);
		if (--default_context_refcnt > 0) {
			usb_dbg("not destroying default context");
			usb_mutex_static_unlock(&default_context_lock);
			return;
		}
		usb_dbg("destroying default context");
		usb_default_context = NULL;
		usb_mutex_static_unlock(&default_context_lock);
	}

	/* a little sanity check. doesn't bother with open_devs locking because
	 * unless there is an application bug, nobody will be accessing this. */
	if (!list_empty(&ctx->open_devs))
		usb_warn(ctx, "application left some devices open");

	usb_io_exit(ctx);
	if (usb_backend->exit)
		usb_backend->exit();

	usb_mutex_destroy(&ctx->open_devs_lock);
	usb_mutex_destroy(&ctx->usb_devs_lock);
	free(ctx);
}

int  libusb_has_capability(uint32_t capability)
{
	enum libusb_capability cap = capability;
	switch (cap) {
	case LIBUSB_CAP_HAS_CAPABILITY:
		return 1;
	}
	return 0;
}

const char * libusb_error_name(int error_code)
{
	enum libusb_error error = error_code;
	switch (error) {
	case LIBUSB_SUCCESS:
		return "LIBUSB_SUCCESS";
	case LIBUSB_ERROR_IO:
		return "LIBUSB_ERROR_IO";
	case LIBUSB_ERROR_INVALID_PARAM:
		return "LIBUSB_ERROR_INVALID_PARAM";
	case LIBUSB_ERROR_ACCESS:
		return "LIBUSB_ERROR_ACCESS";
	case LIBUSB_ERROR_NO_DEVICE:
		return "LIBUSB_ERROR_NO_DEVICE";
	case LIBUSB_ERROR_NOT_FOUND:
		return "LIBUSB_ERROR_NOT_FOUND";
	case LIBUSB_ERROR_BUSY:
		return "LIBUSB_ERROR_BUSY";
	case LIBUSB_ERROR_TIMEOUT:
		return "LIBUSB_ERROR_TIMEOUT";
	case LIBUSB_ERROR_OVERFLOW:
		return "LIBUSB_ERROR_OVERFLOW";
	case LIBUSB_ERROR_PIPE:
		return "LIBUSB_ERROR_PIPE";
	case LIBUSB_ERROR_INTERRUPTED:
		return "LIBUSB_ERROR_INTERRUPTED";
	case LIBUSB_ERROR_NO_MEM:
		return "LIBUSB_ERROR_NO_MEM";
	case LIBUSB_ERROR_NOT_SUPPORTED:
		return "LIBUSB_ERROR_NOT_SUPPORTED";
	case LIBUSB_ERROR_OTHER:
		return "LIBUSB_ERROR_OTHER";
	}
	return "**UNKNOWN**";
}

const struct libusb_version * libusb_get_version(void)
{
	return &libusb_version_internal;
}
