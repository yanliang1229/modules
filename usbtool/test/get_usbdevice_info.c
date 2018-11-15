#include "test.h"

#define EP_INTR			(1 | LIBUSB_ENDPOINT_IN)
#define EP_DATA			(2 | LIBUSB_ENDPOINT_IN)
#define CTRL_IN			(LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_ENDPOINT_IN)
#define CTRL_OUT		(LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_OUT)
#define USB_RQ			0x00
#define INTR_LENGTH		64

static struct libusb_device_handle *devh = NULL;

static int find_my_device(uint16_t vendor_id, uint16_t product_id)
{
	devh = libusb_open_device_with_vid_pid(NULL, vendor_id, product_id);
	return devh ? 0 : -EIO;
}

static int get_hwstat(unsigned char *status)
{
	int r;

	r = libusb_control_transfer(devh, CTRL_IN, USB_RQ, 0x0, 0, status, 2, 0);
	if (r < 0) {
		fprintf(stderr, "read hwstat error %d\n", r);
		return r;
	}
	if ((unsigned int) r < 2) {
		fprintf(stderr, "short read (%d)\n", r);
		return -1;
	}

	printf("hwstat reads %02x\n", *status);
	return 0;
}

static int write_bulk_transfer(unsigned char endpoint, unsigned char *data, int length, unsigned int timeout)
{
	
	int r;
	int transferred;
	r = libusb_bulk_transfer(devh, LIBUSB_ENDPOINT_OUT | endpoint, data, length, &transferred, timeout);
	if (r < 0) {
		fprintf(stderr, "write bulk data error %d\n", r);
		return r;
	}

	return 0;
}

static int read_bulk_transfer(unsigned char endpoint, unsigned char *data, int length, unsigned int timeout)
{
	int transferred;
	return libusb_bulk_transfer(devh, LIBUSB_ENDPOINT_IN | endpoint, data, length, &transferred, timeout);
}

int get_usbdevice_info(void)
{
	struct sigaction sigact;
	int r = 1;
	char status[2];
	char data[32];
	r = libusb_init(NULL);
	if (r < 0) {
		fprintf(stderr, "failed to initialise libusb\n");
		exit(1);
	}

	r =find_my_device(0xaaaa, 0xbbbb);
	if (r < 0) {
		fprintf(stderr, "Could not find/open device\n");
		return r;
	}

	r = libusb_kernel_driver_active(devh, 0);
	if (r == 1) {
		libusb_detach_kernel_driver(devh, 0);
		printf("driver error\n");
	}

	r = libusb_claim_interface(devh, 0);
	if (r < 0) {
		fprintf(stderr, "usb_claim_interface error %d\n", r);
		return r;
	}
	printf("claimed interface\n");

	while (1) {
		r = read_bulk_transfer(1, data, 32, 0);
		printf("read %d  %s\n", r, data);
	}
	return 0;
}

