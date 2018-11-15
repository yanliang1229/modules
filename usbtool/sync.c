
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "log.h"
#include "libusb.h"


static int wait_for_submit(libusb_device_handle *dev_handle, 
		struct libusb_transfer *transfer, unsigned char *data)
{
	int r = 0;
	int *completed = transfer->user_data;
	unsigned char bmRequestType = transfer->type; 

	r = libusb_submit_transfer(transfer);
	if (r < 0) {
		libusb_free_transfer(transfer);
		return r;
	}

	while (*completed == 0) {
		r = libusb_handle_events_completed(HANDLE_CTX(dev_handle), completed);
		if (r < 0) {
			if (r == LIBUSB_ERROR_INTERRUPTED) {
				continue;
			}
			libusb_cancel_transfer(transfer);
			while (!completed)
				if (libusb_handle_events_completed(HANDLE_CTX(dev_handle), completed) < 0)
					break;
			libusb_free_transfer(transfer);
			return r;
		}
	}

	if ((bmRequestType & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN
			&& data)
		memcpy(data, libusb_control_transfer_get_data(transfer),
			transfer->actual_length);

	switch (transfer->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		r = transfer->actual_length;
		break;
	case LIBUSB_TRANSFER_TIMED_OUT:
		r = LIBUSB_ERROR_TIMEOUT;
		break;
	case LIBUSB_TRANSFER_STALL:
		r = LIBUSB_ERROR_PIPE;
		break;
	case LIBUSB_TRANSFER_NO_DEVICE:
		r = LIBUSB_ERROR_NO_DEVICE;
		break;
	case LIBUSB_TRANSFER_OVERFLOW:
		r = LIBUSB_ERROR_OVERFLOW;
		break;
	default:
		usb_warn(HANDLE_CTX(dev_handle),
			"unrecognised status code %d", transfer->status);
		r = LIBUSB_ERROR_OTHER;
	}

	libusb_free_transfer(transfer);
	return r;
	
}

int  libusb_control_transfer(libusb_device_handle *dev_handle,
	uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
	unsigned char *data, uint16_t wLength, unsigned int timeout)
{
	struct libusb_transfer *transfer = _libusb_alloc_transfer(0);
	unsigned char *buffer;
	int r;
	int completed = 0;

	if (!transfer)
		return LIBUSB_ERROR_NO_MEM;

	buffer = malloc(LIBUSB_CONTROL_SETUP_SIZE + wLength);
	if (!buffer) {
		libusb_free_transfer(transfer);
		return LIBUSB_ERROR_NO_MEM;
	}

	libusb_fill_control_setup(buffer, bmRequestType, bRequest, wValue, wIndex,
		wLength);
	if ((bmRequestType & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT)
		memcpy(buffer + LIBUSB_CONTROL_SETUP_SIZE, data, wLength);

	libusb_fill_control_transfer(transfer, dev_handle, buffer,
		transfer_callback, &completed, timeout);
	transfer->flags = LIBUSB_TRANSFER_FREE_BUFFER;
	return wait_for_submit(dev_handle,transfer, data); 
}

void transfer_callback(struct libusb_transfer *transfer)
{
	int *completed = transfer->user_data;
	*completed = 1;
	usb_dbg("actual_length=%d", transfer->actual_length);
}

static int do_sync_bulk_transfer(struct libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *buffer, int length,
	int *transferred, unsigned int timeout, unsigned char type)
{
	struct libusb_transfer *transfer = _libusb_alloc_transfer(0);
	int completed = 0;
	int r;

	if (!transfer)
		return LIBUSB_ERROR_NO_MEM;

	libusb_fill_bulk_transfer(transfer, dev_handle, endpoint, buffer, length,
		transfer_callback, &completed, timeout);
	transfer->type = type;
/*
	r = libusb_submit_transfer(transfer);
	if (r < 0) {
		libusb_free_transfer(transfer);
		return r;
	}
	*/
	return wait_for_submit(dev_handle,transfer, NULL); 
}


int libusb_bulk_transfer(struct libusb_device_handle *dev_handle,
	unsigned char endpoint, unsigned char *data, int length, int *transferred,
	unsigned int timeout)
{
	return do_sync_bulk_transfer(dev_handle, endpoint, data, length,
		transferred, timeout, LIBUSB_TRANSFER_TYPE_BULK);
}


int libusb_interrupt_transfer(
	struct libusb_device_handle *dev_handle, unsigned char endpoint,
	unsigned char *data, int length, int *transferred, unsigned int timeout)
{
	return do_sync_bulk_transfer(dev_handle, endpoint, data, length,
		transferred, timeout, LIBUSB_TRANSFER_TYPE_INTERRUPT);
}

