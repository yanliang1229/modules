#ifndef LIBUSB_H
#define LIBUSB_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <poll.h>
#include <sys/types.h>
#include <limits.h>

#include "common.h"


int libusb_init(libusb_context **ctx);

void libusb_exit(libusb_context *ctx);

const struct libusb_version * libusb_get_version(void);

int  libusb_kernel_driver_active(libusb_device_handle *dev,
	int interface_number);

int  libusb_detach_kernel_driver(libusb_device_handle *dev,
	int interface_number);

int  libusb_attach_kernel_driver(libusb_device_handle *dev,
	int interface_number);
ssize_t libusb_get_device_list(libusb_context *ctx,
	libusb_device ***list);

void libusb_free_device_list(libusb_device **list,
	int unref_devices);

int libusb_get_configuration(libusb_device_handle *dev,
	int *config);

int libusb_get_device_descriptor(libusb_device *dev,
	struct libusb_device_descriptor *desc);

int libusb_get_string_descriptor_ascii(libusb_device_handle *dev,
	uint8_t desc_index, unsigned char *data, int length);

int libusb_get_active_config_descriptor(libusb_device *dev,
	struct libusb_config_descriptor **config);

int libusb_get_config_descriptor(libusb_device *dev,
	uint8_t config_index, struct libusb_config_descriptor **config);

int libusb_get_config_descriptor_by_value(libusb_device *dev,
	uint8_t bConfigurationValue, struct libusb_config_descriptor **config);

void libusb_free_config_descriptor(
	struct libusb_config_descriptor *config);

uint8_t libusb_get_bus_number(libusb_device *dev);

uint8_t libusb_get_device_address(libusb_device *dev);

int libusb_get_device_speed(libusb_device *dev);

int libusb_get_max_packet_size(libusb_device *dev,
	unsigned char endpoint);

int libusb_get_endpoint_type(libusb_device *dev,
	unsigned char endpoint);

int libusb_get_max_iso_packet_size(libusb_device *dev,
	unsigned char endpoint);

libusb_device_handle *libusb_open_device_with_vid_pid(
	libusb_context *ctx, uint16_t vendor_id, uint16_t product_id);

void libusb_close_device(libusb_device_handle *dev);

int libusb_reset_device(libusb_device_handle *dev);

struct libusb_transfer *libusb_alloc_transfer(int iso_packets);

void libusb_free_transfer(struct libusb_transfer *transfer);

int libusb_submit_transfer(struct libusb_transfer *transfer);

int libusb_cancel_transfer(struct libusb_transfer *transfer);

int libusb_bulk_transfer(libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length,
	int *actual_length, unsigned int timeout);

int libusb_interrupt_transfer(libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length,
	int *actual_length, unsigned int timeout);

int libusb_control_transfer(libusb_device_handle *dev_handle,
	uint8_t request_type, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
	unsigned char *data, uint16_t wLength, unsigned int timeout);

int libusb_show_device(uint16_t vendor_id, uint16_t product_id);

int libusb_show_all_devices();

#endif

