#ifndef LIBUSBI_H
#define LIBUSBI_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <poll.h>
#include <sys/types.h>
#include <limits.h>
#include "threads_posix.h"
#include "poll_posix.h"

#include "version.h"
#include "list.h"
#include "log.h"


#define API_EXPORTED LIBUSB_CALL 

#define DEVICE_DESC_LENGTH		18

#define USB_MAXENDPOINTS	32
#define USB_MAXINTERFACES	32
#define USB_MAXCONFIG		8
#define ENABLE_LOGGING

# define TIMEVAL_TO_TIMESPEC(tv, ts) {                                   \
	(ts)->tv_sec = (tv)->tv_sec;                                    \
	(ts)->tv_nsec = (tv)->tv_usec * 1000;                           \
}
# define TIMESPEC_TO_TIMEVAL(tv, ts) {                                   \
	(tv)->tv_sec = (ts)->tv_sec;                                    \
	(tv)->tv_usec = (ts)->tv_nsec / 1000;                           \
}

#define container_of(ptr, type, member) ({                      \
        typeof( ((type *)0)->member ) *mptr = (ptr);    \
        (type *)( (char *)mptr - offsetof(type,member) );})

#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

#define TIMESPEC_IS_SET(ts) ((ts)->tv_sec != 0 || (ts)->tv_nsec != 0)

enum usb_log_level {
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_INFO,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_ERROR,
};

static inline uint16_t libusb_cpu_to_le16(const uint16_t x)
{
	union {
		uint8_t  b8[2];
		uint16_t b16;
	} _tmp;
	_tmp.b8[1] = x >> 8;
	_tmp.b8[0] = x & 0xff;
	return _tmp.b16;
}

#define libusb_le16_to_cpu libusb_cpu_to_le16

enum libusb_class_code {
	LIBUSB_CLASS_PER_INTERFACE = 0,
	LIBUSB_CLASS_AUDIO = 1,
	LIBUSB_CLASS_COMM = 2,
	LIBUSB_CLASS_HID = 3,
	LIBUSB_CLASS_PHYSICAL = 5,
	LIBUSB_CLASS_PRINTER = 7,
	LIBUSB_CLASS_PTP = 6, /* legacy name from libusb-0.1 usb.h */
	LIBUSB_CLASS_IMAGE = 6,
	LIBUSB_CLASS_MASS_STORAGE = 8,
	LIBUSB_CLASS_HUB = 9,
	LIBUSB_CLASS_DATA = 10,
	LIBUSB_CLASS_SMART_CARD = 0x0b,
	LIBUSB_CLASS_CONTENT_SECURITY = 0x0d,
	LIBUSB_CLASS_VIDEO = 0x0e,
	LIBUSB_CLASS_PERSONAL_HEALTHCARE = 0x0f,
	LIBUSB_CLASS_DIAGNOSTIC_DEVICE = 0xdc,
	LIBUSB_CLASS_WIRELESS = 0xe0,
	LIBUSB_CLASS_APPLICATION = 0xfe,
	LIBUSB_CLASS_VENDOR_SPEC = 0xff
};

enum libusb_descriptor_type {
	LIBUSB_DT_DEVICE = 0x01,
	LIBUSB_DT_CONFIG = 0x02,
	LIBUSB_DT_STRING = 0x03,
	LIBUSB_DT_INTERFACE = 0x04,
	LIBUSB_DT_ENDPOINT = 0x05,
	LIBUSB_DT_HID = 0x21,
	LIBUSB_DT_REPORT = 0x22,
	LIBUSB_DT_PHYSICAL = 0x23,
	LIBUSB_DT_HUB = 0x29,
};

/* Descriptor sizes per descriptor type */
#define LIBUSB_DT_DEVICE_SIZE			18
#define LIBUSB_DT_CONFIG_SIZE			9
#define LIBUSB_DT_INTERFACE_SIZE		9
#define LIBUSB_DT_ENDPOINT_SIZE		7
#define LIBUSB_DT_ENDPOINT_AUDIO_SIZE	9	/* Audio extension */
#define LIBUSB_DT_HUB_NONVAR_SIZE		7

#define LIBUSB_ENDPOINT_ADDRESS_MASK	0x0f    /* in bEndpointAddress */
#define LIBUSB_ENDPOINT_DIR_MASK		0x80

enum libusb_endpoint_direction {
	LIBUSB_ENDPOINT_IN = 0x80,
	LIBUSB_ENDPOINT_OUT = 0x00
};

#define LIBUSB_TRANSFER_TYPE_MASK			0x03    /* in bmAttributes */

enum libusb_transfer_type {
	LIBUSB_TRANSFER_TYPE_CONTROL = 0,
	LIBUSB_TRANSFER_TYPE_ISOCHRONOUS = 1,
	LIBUSB_TRANSFER_TYPE_BULK = 2,
	LIBUSB_TRANSFER_TYPE_INTERRUPT = 3
};

enum libusb_standard_request {
	LIBUSB_REQUEST_GET_STATUS = 0x00,
	LIBUSB_REQUEST_CLEAR_FEATURE = 0x01,
	LIBUSB_REQUEST_SET_FEATURE = 0x03,
	LIBUSB_REQUEST_SET_ADDRESS = 0x05,
	LIBUSB_REQUEST_GET_DESCRIPTOR = 0x06,
	LIBUSB_REQUEST_SET_DESCRIPTOR = 0x07,
	LIBUSB_REQUEST_GET_CONFIGURATION = 0x08,
	LIBUSB_REQUEST_SET_CONFIGURATION = 0x09,
	LIBUSB_REQUEST_GET_INTERFACE = 0x0A,
	LIBUSB_REQUEST_SET_INTERFACE = 0x0B,
	LIBUSB_REQUEST_SYNCH_FRAME = 0x0C,
};

/**
 * Request type bits of the
 */
enum libusb_request_type {
	LIBUSB_REQUEST_TYPE_STANDARD = (0x00 << 5),
	LIBUSB_REQUEST_TYPE_CLASS = (0x01 << 5),
	LIBUSB_REQUEST_TYPE_VENDOR = (0x02 << 5),
	LIBUSB_REQUEST_TYPE_RESERVED = (0x03 << 5)
};

/**
 * Recipient bits of the
*/
enum libusb_request_recipient {
	LIBUSB_RECIPIENT_DEVICE = 0x00,
	LIBUSB_RECIPIENT_INTERFACE = 0x01,
	LIBUSB_RECIPIENT_ENDPOINT = 0x02,
	LIBUSB_RECIPIENT_OTHER = 0x03,
};

#define LIBUSB_ISO_SYNC_TYPE_MASK		0x0C

enum libusb_iso_sync_type {
	LIBUSB_ISO_SYNC_TYPE_NONE = 0,
	LIBUSB_ISO_SYNC_TYPE_ASYNC = 1,
	LIBUSB_ISO_SYNC_TYPE_ADAPTIVE = 2,
	LIBUSB_ISO_SYNC_TYPE_SYNC = 3
};

#define LIBUSB_ISO_USAGE_TYPE_MASK 0x30

enum libusb_iso_usage_type {
	LIBUSB_ISO_USAGE_TYPE_DATA = 0,
	LIBUSB_ISO_USAGE_TYPE_FEEDBACK = 1,
	LIBUSB_ISO_USAGE_TYPE_IMPLICIT = 2,
};

enum libusb_speed {
    LIBUSB_SPEED_UNKNOWN = 0,
    LIBUSB_SPEED_LOW = 1,
    LIBUSB_SPEED_FULL = 2,
    LIBUSB_SPEED_HIGH = 3,
    LIBUSB_SPEED_SUPER = 4,
};

enum libusb_error {
	LIBUSB_SUCCESS = 0,
	LIBUSB_ERROR_IO = -1,
	LIBUSB_ERROR_INVALID_PARAM = -2,
	LIBUSB_ERROR_ACCESS = -3,
	LIBUSB_ERROR_NO_DEVICE = -4,
	LIBUSB_ERROR_NOT_FOUND = -5,
	LIBUSB_ERROR_BUSY = -6,
	LIBUSB_ERROR_TIMEOUT = -7,
	LIBUSB_ERROR_OVERFLOW = -8,
	LIBUSB_ERROR_PIPE = -9,
	LIBUSB_ERROR_INTERRUPTED = -10,
	LIBUSB_ERROR_NO_MEM = -11,
	LIBUSB_ERROR_NOT_SUPPORTED = -12,
	LIBUSB_ERROR_OTHER = -99,
};

enum libusb_transfer_status {
	LIBUSB_TRANSFER_COMPLETED,
	LIBUSB_TRANSFER_ERROR,
	LIBUSB_TRANSFER_TIMED_OUT,
	LIBUSB_TRANSFER_CANCELLED,
	LIBUSB_TRANSFER_STALL,
	LIBUSB_TRANSFER_NO_DEVICE,
	LIBUSB_TRANSFER_OVERFLOW,
};

enum libusb_transfer_flags {
	LIBUSB_TRANSFER_SHORT_NOT_OK = 1<<0,
	LIBUSB_TRANSFER_FREE_BUFFER = 1<<1,
	LIBUSB_TRANSFER_FREE_TRANSFER = 1<<2,
	LIBUSB_TRANSFER_ADD_ZERO_PACKET = 1 << 3,
};
enum {
  USBI_CLOCK_MONOTONIC,
  USBI_CLOCK_REALTIME
};

struct libusb_device_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdUSB;
	uint8_t  bDeviceClass;
	uint8_t  bDeviceSubClass;
	uint8_t  bDeviceProtocol;
	uint8_t  bMaxPacketSize0;
	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;
	uint8_t  iManufacturer;
	uint8_t  iProduct;
	uint8_t  iSerialNumber;
	uint8_t  bNumConfigurations;
};

struct libusb_endpoint_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bEndpointAddress;
	uint8_t  bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t  bInterval;
	uint8_t  bRefresh;
	uint8_t  bSynchAddress;
	unsigned char *extra;
	int extra_length;
};

struct libusb_interface_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bInterfaceNumber;
	uint8_t  bAlternateSetting;
	uint8_t  bNumEndpoints;
	uint8_t  bInterfaceClass;
	uint8_t  bInterfaceSubClass;
	uint8_t  bInterfaceProtocol;
	uint8_t  iInterface;
	struct libusb_endpoint_descriptor *endpoint;
	unsigned char *extra;
	int extra_length;
};

struct libusb_interface {
	struct libusb_interface_descriptor *altsetting;
	int num_altsetting;
};

struct libusb_config_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t wTotalLength;
	uint8_t  bNumInterfaces;
	uint8_t  bConfigurationValue;
	uint8_t  iConfiguration;
	uint8_t  bmAttributes;
	uint8_t  MaxPower;
	struct libusb_interface *interface;
	unsigned char *extra;
	int extra_length;
};

struct libusb_control_setup {
	uint8_t  bmRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
};

#define LIBUSB_CONTROL_SETUP_SIZE (sizeof(struct libusb_control_setup))

typedef void (*libusb_pollfd_added_cb)(int fd, short events,
	void *user_data);

typedef void (*libusb_pollfd_removed_cb)(int fd, void *user_data);

typedef struct libusb_context {
	int debug;
	int debug_fixed;

	int ctrl_pipe[2];

	struct list_head usb_devs;
	usb_mutex_t usb_devs_lock;

	struct list_head open_devs;
	usb_mutex_t open_devs_lock;
	
	struct list_head flying_transfers;
	usb_mutex_t flying_transfers_lock;

	struct list_head pollfds;
	usb_mutex_t pollfds_lock;

	unsigned int pollfd_modify;
	usb_mutex_t pollfd_modify_lock;

	libusb_pollfd_added_cb fd_added_cb;
	libusb_pollfd_removed_cb fd_removed_cb;
	void *fd_cb_user_data;

	usb_mutex_t events_lock;
	int event_handler_active;
	usb_mutex_t event_waiters_lock;
	usb_cond_t event_waiters_cond;
}libusb_context;

typedef struct libusb_device {
	usb_mutex_t lock;
	int refcnt;

	struct libusb_context *ctx;

	uint8_t bus_number;
	uint8_t device_address;
	uint8_t num_configurations;
	enum libusb_speed speed;

	struct list_head list;
	unsigned long session_data;
	unsigned char os_priv[0];
}libusb_device;

typedef struct libusb_device_handle {
	usb_mutex_t lock;
	unsigned long claimed_interfaces;

	struct list_head list;
	struct libusb_device *dev;
	unsigned char os_priv[0];
}libusb_device_handle;


struct libusb_version {
	const uint16_t major;
	const uint16_t minor;
	const uint16_t micro;
	const uint16_t nano;
	const char *rc;

	const char *describe;
};

struct libusb_iso_packet_descriptor {
	unsigned int length;
	unsigned int actual_length;
	enum libusb_transfer_status status;
};

/** 
 * File descriptor for polling
 */
struct libusb_pollfd {
	int fd;
	short events;
};

struct libusb_transfer;
typedef void ( *libusb_transfer_cb_fn)(struct libusb_transfer *transfer);
struct libusb_transfer {
	libusb_device_handle *dev_handle;
	uint8_t flags;
	unsigned char endpoint;
	unsigned char type;
	unsigned int timeout;
	enum libusb_transfer_status status;
	int length;
	int actual_length;
	libusb_transfer_cb_fn callback;
	void *user_data;
	unsigned char *buffer;
	int num_iso_packets;
	struct libusb_iso_packet_descriptor iso_packet_desc[0];
};

enum libusb_capability {
	LIBUSB_CAP_HAS_CAPABILITY = 0,
};

#define USBI_GET_CONTEXT(ctx) if (!(ctx)) (ctx) = usb_default_context
#define DEVICE_CTX(dev) ((dev)->ctx)
#define HANDLE_CTX(handle) (DEVICE_CTX((handle)->dev))
#define TRANSFER_CTX(transfer) (HANDLE_CTX((transfer)->dev_handle))
#define ITRANSFER_CTX(transfer) \
	(TRANSFER_CTX(USBI_TRANSFER_TO_LIBUSB_TRANSFER(transfer)))

#define IS_EPIN(ep) (0 != ((ep) & LIBUSB_ENDPOINT_IN))
#define IS_EPOUT(ep) (!IS_EPIN(ep))
#define IS_XFERIN(xfer) (0 != ((xfer)->endpoint & LIBUSB_ENDPOINT_IN))
#define IS_XFEROUT(xfer) (!IS_XFERIN(xfer))

#define usb_gettimeofday(tv, tz) gettimeofday((tv), (tz))
#define HAVE_USBI_GETTIMEOFDAY

extern struct libusb_context *usb_default_context;

struct usb_transfer {
	int num_iso_packets;
	struct list_head list;
	struct timeval timeout;
	int transferred;
	uint8_t flags;
	usb_mutex_t lock;
};

enum usb_transfer_flags {
	USBI_TRANSFER_TIMED_OUT = 1 << 0,
	USBI_TRANSFER_OS_HANDLES_TIMEOUT = 1 << 1,
	USBI_TRANSFER_CANCELLING = 1 << 2,
	USBI_TRANSFER_DEVICE_DISAPPEARED = 1 << 3,
};

#define USBI_TRANSFER_TO_LIBUSB_TRANSFER(transfer) \
	((struct libusb_transfer *)(((unsigned char *)(transfer)) \
		+ sizeof(struct usb_transfer)))
#define LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer) \
	((struct usb_transfer *)(((unsigned char *)(transfer)) \
		- sizeof(struct usb_transfer)))

static inline void *usb_transfer_get_os_priv(struct usb_transfer *transfer)
{
	return ((unsigned char *)transfer) + sizeof(struct usb_transfer)
		+ sizeof(struct libusb_transfer)
		+ (transfer->num_iso_packets
			* sizeof(struct libusb_iso_packet_descriptor));
}

/* bus structures */

/* All standard descriptors have these 2 fields in common */
struct usb_descriptor_header {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
};

/* shared data and functions */

int usb_io_init(struct libusb_context *ctx);
void usb_io_exit(struct libusb_context *ctx);

void  libusb_set_debug(libusb_context *ctx, int level);
const char *  libusb_error_name(int errcode);
int  libusb_has_capability(uint32_t capability);
struct libusb_device *usb_alloc_device(struct libusb_context *ctx,
	unsigned long session_id);
struct libusb_device *usb_get_device_by_session_id(struct libusb_context *ctx,
	unsigned long session_id);
int usb_sanitize_device(struct libusb_device *dev);
void usb_handle_disconnect(struct libusb_device_handle *handle);

int usb_handle_transfer_completion(struct usb_transfer *itransfer,
	enum libusb_transfer_status status);
int usb_handle_transfer_cancellation(struct usb_transfer *transfer);

int usb_parse_descriptor(unsigned char *source, const char *descriptor,
	void *dest, int host_endian);
int usb_get_config_index_by_value(struct libusb_device *dev,
	uint8_t bConfigurationValue, int *idx);

/* polling */

struct usb_pollfd {
	struct libusb_pollfd pollfd;
	struct list_head list;
};

int usb_add_pollfd(struct libusb_context *ctx, int fd, short events);
void usb_remove_pollfd(struct libusb_context *ctx, int fd);
void usb_fd_notification(struct libusb_context *ctx);

struct discovered_devs {
	size_t len;
	size_t capacity;
	struct libusb_device *devices[0];
};

struct discovered_devs *discovered_devs_append(
	struct discovered_devs *discdevs, struct libusb_device *dev);

/* OS abstraction */

/* This is the interface that OS backends need to implement.
 * All fields are mandatory, except ones explicitly noted as optional. */
struct usb_os_backend {
	/* A human-readable name for your backend, e.g. "Linux usbfs" */
	const char *name;
	int (*init)(struct libusb_context *ctx);
	void (*exit)(void);
	int (*get_device_list)(struct libusb_context *ctx,
		struct discovered_devs **discdevs);
	int (*open)(struct libusb_device_handle *handle);
	void (*close)(struct libusb_device_handle *handle);
	int (*get_device_descriptor)(struct libusb_device *device,
		unsigned char *buffer, int *host_endian);
	int (*get_active_config_descriptor)(struct libusb_device *device,
		unsigned char *buffer, size_t len, int *host_endian);
	int (*get_config_descriptor)(struct libusb_device *device,
		uint8_t config_index, unsigned char *buffer, size_t len,
		int *host_endian);
	int (*get_configuration)(struct libusb_device_handle *handle, int *config);
	int (*set_configuration)(struct libusb_device_handle *handle, int config);
	int (*claim_interface)(struct libusb_device_handle *handle, int interface_number);
	int (*release_interface)(struct libusb_device_handle *handle, int interface_number);
	int (*set_interface_altsetting)(struct libusb_device_handle *handle,
		int interface_number, int altsetting);
	int (*clear_halt)(struct libusb_device_handle *handle,
		unsigned char endpoint);
	int (*reset_device)(struct libusb_device_handle *handle);
	int (*kernel_driver_active)(struct libusb_device_handle *handle,
		int interface_number);

	int (*detach_kernel_driver)(struct libusb_device_handle *handle,
		int interface_number);

	int (*attach_kernel_driver)(struct libusb_device_handle *handle,
		int interface_number);

	void (*destroy_device)(struct libusb_device *dev);

	int (*submit_transfer)(struct usb_transfer *itransfer);

	int (*cancel_transfer)(struct usb_transfer *itransfer);

	void (*clear_transfer_priv)(struct usb_transfer *itransfer);

	int (*handle_events)(struct libusb_context *ctx,
		struct pollfd *fds, int cnt, int num_ready);

	int (*clock_gettime)(int clkid, struct timespec *tp);

	size_t device_priv_size;
	size_t device_handle_priv_size;
	size_t transfer_priv_size;
	size_t add_iso_packet_size;
};

extern const struct usb_os_backend * const usb_backend;
extern const struct usb_os_backend linux_usbfs_backend;

static inline unsigned char *libusb_control_transfer_get_data(
	struct libusb_transfer *transfer)
{
	return transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE;
}

static inline struct libusb_control_setup *libusb_control_transfer_get_setup(
	struct libusb_transfer *transfer)
{
	return (struct libusb_control_setup *) transfer->buffer;
}

void transfer_callback(struct libusb_transfer *transfer);

static inline void libusb_fill_control_setup(unsigned char *buffer,
	uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
	uint16_t wLength)
{
	struct libusb_control_setup *setup = (struct libusb_control_setup *) buffer;
	setup->bmRequestType = bmRequestType;
	setup->bRequest = bRequest;
	setup->wValue = libusb_cpu_to_le16(wValue);
	setup->wIndex = libusb_cpu_to_le16(wIndex);
	setup->wLength = libusb_cpu_to_le16(wLength);
}

static inline void libusb_fill_control_transfer(
	struct libusb_transfer *transfer, libusb_device_handle *dev_handle,
	unsigned char *buffer, libusb_transfer_cb_fn callback, void *user_data,
	unsigned int timeout)
{
	struct libusb_control_setup *setup = (struct libusb_control_setup *) buffer;
	transfer->dev_handle = dev_handle;
	transfer->endpoint = 0;
	transfer->type = LIBUSB_TRANSFER_TYPE_CONTROL;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	if (setup)
		transfer->length = LIBUSB_CONTROL_SETUP_SIZE
			+ libusb_le16_to_cpu(setup->wLength);
	transfer->user_data = user_data;
	transfer->callback = callback;
}

static inline void libusb_fill_bulk_transfer(struct libusb_transfer *transfer,
	libusb_device_handle *dev_handle, unsigned char endpoint,
	unsigned char *buffer, int length, libusb_transfer_cb_fn callback,
	void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = endpoint;
	transfer->type = LIBUSB_TRANSFER_TYPE_BULK;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

static inline void libusb_fill_interrupt_transfer(
	struct libusb_transfer *transfer, libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *buffer, int length,
	libusb_transfer_cb_fn callback, void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = endpoint;
	transfer->type = LIBUSB_TRANSFER_TYPE_INTERRUPT;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

static inline void libusb_fill_iso_transfer(struct libusb_transfer *transfer,
	libusb_device_handle *dev_handle, unsigned char endpoint,
	unsigned char *buffer, int length, int num_iso_packets,
	libusb_transfer_cb_fn callback, void *user_data, unsigned int timeout)
{
	transfer->dev_handle = dev_handle;
	transfer->endpoint = endpoint;
	transfer->type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;
	transfer->timeout = timeout;
	transfer->buffer = buffer;
	transfer->length = length;
	transfer->num_iso_packets = num_iso_packets;
	transfer->user_data = user_data;
	transfer->callback = callback;
}

static inline void libusb_set_iso_packet_lengths(
	struct libusb_transfer *transfer, unsigned int length)
{
	int i;
	for (i = 0; i < transfer->num_iso_packets; i++)
		transfer->iso_packet_desc[i].length = length;
}

static inline unsigned char *libusb_get_iso_packet_buffer(
	struct libusb_transfer *transfer, unsigned int packet)
{
	int i;
	size_t offset = 0;
	int _packet;

	/* oops..slight bug in the API. packet is an unsigned int, but we use
	 * signed integers almost everywhere else. range-check and convert to
	 * signed to avoid compiler warnings. FIXME for libusb-2. */
	if (packet > INT_MAX)
		return NULL;
	_packet = packet;

	if (_packet >= transfer->num_iso_packets)
		return NULL;

	for (i = 0; i < _packet; i++)
		offset += transfer->iso_packet_desc[i].length;

	return transfer->buffer + offset;
}

static inline unsigned char *libusb_get_iso_packet_buffer_simple(
	struct libusb_transfer *transfer, unsigned int packet)
{
	int _packet;

	if (packet > INT_MAX)
		return NULL;
	_packet = packet;

	if (_packet >= transfer->num_iso_packets)
		return NULL;

	return transfer->buffer + (transfer->iso_packet_desc[0].length * _packet);
}

int  libusb_open(libusb_device *dev, libusb_device_handle **handle);
void  libusb_close(libusb_device_handle *dev_handle);
libusb_device *  libusb_get_device(libusb_device_handle *dev_handle);
/* sync I/O */

/* polling and timeouts */

void  libusb_lock_events(libusb_context *ctx);
void  libusb_unlock_events(libusb_context *ctx);
int  libusb_event_handling_ok(libusb_context *ctx);

int  libusb_handle_events_completed(libusb_context *ctx, int *completed);

libusb_device_handle *  _libusb_open_device_with_vid_pid(
	libusb_context *ctx, uint16_t vendor_id, uint16_t product_id);
struct libusb_transfer *  _libusb_alloc_transfer(int iso_packets);

int  libusb_control_transfer(libusb_device_handle *dev_handle,
	uint8_t request_type, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
	unsigned char *data, uint16_t wLength, unsigned int timeout);
libusb_device *libusb_ref_device(libusb_device *dev);
void  libusb_unref_device(libusb_device *dev);

static inline int libusb_get_descriptor(libusb_device_handle *dev,
	uint8_t desc_type, uint8_t desc_index, unsigned char *data, int length)
{
	return libusb_control_transfer(dev, LIBUSB_ENDPOINT_IN,
		LIBUSB_REQUEST_GET_DESCRIPTOR, (desc_type << 8) | desc_index, 0, data,
		(uint16_t) length, 1000);
}
static inline int libusb_get_string_descriptor(libusb_device_handle *dev,
	uint8_t desc_index, uint16_t langid, unsigned char *data, int length)
{
	return libusb_control_transfer(dev, LIBUSB_ENDPOINT_IN,
		LIBUSB_REQUEST_GET_DESCRIPTOR, (uint16_t)((LIBUSB_DT_STRING << 8) | desc_index),
		langid, data, (uint16_t) length, 1000);
}
int  libusb_set_configuration(libusb_device_handle *dev,
	int configuration);
int  libusb_claim_interface(libusb_device_handle *dev,
	int interface_number);
int  libusb_release_interface(libusb_device_handle *dev,
	int interface_number);
int  libusb_set_interface_alt_setting(libusb_device_handle *dev,
	int interface_number, int alternate_setting);
int  libusb_clear_halt(libusb_device_handle *dev,
	unsigned char endpoint);
#endif

