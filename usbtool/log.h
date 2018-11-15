#ifndef LOG_H_
#define LOG_H_

#include "common.h"
#ifdef ENABLE_LOGGING
void usb_log(struct libusb_context *ctx, enum usb_log_level level,
	const char *function, const char *format, ...);

void usb_log_v(struct libusb_context *ctx, enum usb_log_level level,
	const char *function, const char *format, va_list args);
#define _usb_log(ctx, level, ...) usb_log(ctx, level, __FUNCTION__, __VA_ARGS__)
static inline void usb_info(struct libusb_context *ctx, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	usb_log_v(ctx, LOG_LEVEL_INFO, "", fmt, args);
	va_end(args);
}

static inline void usb_warn(struct libusb_context *ctx, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	usb_log_v(ctx, LOG_LEVEL_WARNING, "", fmt, args);
	va_end(args);
}

static inline void usb_err(struct libusb_context *ctx, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	usb_log_v(ctx, LOG_LEVEL_ERROR, "", fmt, args);
	va_end(args);
}

static inline void usb_dbg(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	usb_log_v(NULL, LOG_LEVEL_DEBUG, "", fmt, args);
	va_end(args);
}
#else
#define _usb_log(ctx, level, ...) do { (void)(ctx); } while(0)
#define usb_info(ctx, ...) _usb_log(ctx, LOG_LEVEL_INFO, __VA_ARGS__)
#define usb_warn(ctx, ...) _usb_log(ctx, LOG_LEVEL_WARNING, __VA_ARGS__)
#define usb_err(ctx, ...) _usb_log(ctx, LOG_LEVEL_ERROR, __VA_ARGS__)
#define usb_dbg(...) do {} while(0)
#endif

#endif
