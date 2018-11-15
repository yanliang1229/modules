#ifndef LIBUSB_POLL_POSIX_H
#define LIBUSB_POLL_POSIX_H

#include <unistd.h>

#define usb_write write
#define usb_read read
#define usb_close close
#define usb_pipe pipe
#define usb_poll poll

#endif /* LIBUSB_POLL_POSIX_H */
