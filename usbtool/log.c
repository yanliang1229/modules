#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#include "common.h"

void usb_log_v(struct libusb_context *ctx, enum usb_log_level level,
	const char *function, const char *format, va_list args)
{
	FILE *stream = stdout;
	const char *prefix;
	struct timeval now;
	static struct timeval first = { 0, 0 };

	USBI_GET_CONTEXT(ctx);
	if (!ctx->debug)
		return;
	if (level == LOG_LEVEL_WARNING && ctx->debug < 2)
		return;
	if (level == LOG_LEVEL_INFO && ctx->debug < 3)
		return;

	usb_gettimeofday(&now, NULL);
	if (!first.tv_sec) {
		first.tv_sec = now.tv_sec;
		first.tv_usec = now.tv_usec;
	}
	if (now.tv_usec < first.tv_usec) {
		now.tv_sec--;
		now.tv_usec += 1000000;
	}
	now.tv_sec -= first.tv_sec;
	now.tv_usec -= first.tv_usec;

	switch (level) {
	case LOG_LEVEL_INFO:
		prefix = "info";
		break;
	case LOG_LEVEL_WARNING:
		stream = stderr;
		prefix = "warning";
		break;
	case LOG_LEVEL_ERROR:
		stream = stderr;
		prefix = "error";
		break;
	case LOG_LEVEL_DEBUG:
		stream = stderr;
		prefix = "debug";
		break;
	default:
		stream = stderr;
		prefix = "unknown";
		break;
	}

	fprintf(stream, "libusb: %d.%06d %s [%s] ",
		(int)now.tv_sec, (int)now.tv_usec, prefix, function);

	vfprintf(stream, format, args);

	fprintf(stream, "\n");
}

void usb_log(struct libusb_context *ctx, enum usb_log_level level,
	const char *function, const char *format, ...)
{
	va_list args;

	va_start (args, format);
	usb_log_v(ctx, level, function, format, args);
	va_end (args);
}
