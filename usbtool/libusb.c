#include "common.h"
struct libusb_transfer *libusb_alloc_transfer(int iso_packets)
{
	return 	_libusb_alloc_transfer(iso_packets);
}

libusb_device_handle *  libusb_open_device_with_vid_pid(
	libusb_context *ctx, uint16_t vendor_id, uint16_t product_id)
{
	return _libusb_open_device_with_vid_pid(ctx, vendor_id, product_id);
}
