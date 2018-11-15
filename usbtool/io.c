#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>

#include "common.h"

int usb_io_init(struct libusb_context *ctx)
{
	int r;

	usb_mutex_init(&ctx->flying_transfers_lock, NULL);
	usb_mutex_init(&ctx->pollfds_lock, NULL);
	usb_mutex_init(&ctx->pollfd_modify_lock, NULL);
	usb_mutex_init_recursive(&ctx->events_lock, NULL);
	usb_mutex_init(&ctx->event_waiters_lock, NULL);
	usb_cond_init(&ctx->event_waiters_cond, NULL);
	list_init(&ctx->flying_transfers);
	list_init(&ctx->pollfds);

	r = usb_pipe(ctx->ctrl_pipe);
	if (r < 0) {
		r = LIBUSB_ERROR_OTHER;
		goto err;
	}

	r = usb_add_pollfd(ctx, ctx->ctrl_pipe[0], POLLIN);
	if (r < 0)
		goto err_close_pipe;

	return 0;

err_close_pipe:
	usb_close(ctx->ctrl_pipe[0]);
	usb_close(ctx->ctrl_pipe[1]);
err:
	usb_mutex_destroy(&ctx->flying_transfers_lock);
	usb_mutex_destroy(&ctx->pollfds_lock);
	usb_mutex_destroy(&ctx->pollfd_modify_lock);
	usb_mutex_destroy(&ctx->events_lock);
	usb_mutex_destroy(&ctx->event_waiters_lock);
	usb_cond_destroy(&ctx->event_waiters_cond);
	return r;
}

void usb_io_exit(struct libusb_context *ctx)
{
	usb_remove_pollfd(ctx, ctx->ctrl_pipe[0]);
	usb_close(ctx->ctrl_pipe[0]);
	usb_close(ctx->ctrl_pipe[1]);
	usb_mutex_destroy(&ctx->flying_transfers_lock);
	usb_mutex_destroy(&ctx->pollfds_lock);
	usb_mutex_destroy(&ctx->pollfd_modify_lock);
	usb_mutex_destroy(&ctx->events_lock);
	usb_mutex_destroy(&ctx->event_waiters_lock);
	usb_cond_destroy(&ctx->event_waiters_cond);
}

/**
 * calculate_timeout：计算出tranfer传输的绝对超时时间(想对于被提交的时刻算起)
 */
static int calculate_timeout(struct usb_transfer *transfer)
{
	int r;
	struct timespec current_time;
	unsigned int timeout =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(transfer)->timeout;

	if (!timeout)
		return 0;

	r = usb_backend->clock_gettime(USBI_CLOCK_MONOTONIC, &current_time);
	if (r < 0) {
		usb_err(ITRANSFER_CTX(transfer),
			"failed to read monotonic clock, errno=%d", errno);
		return r;
	}

	current_time.tv_sec += timeout / 1000;
	current_time.tv_nsec += (timeout % 1000) * 1000000;

	if (current_time.tv_nsec > 1000000000) {
		current_time.tv_nsec -= 1000000000;
		current_time.tv_sec++;
	}

	TIMESPEC_TO_TIMEVAL(&transfer->timeout, &current_time);
	return 0;
}

static void add_to_flying_list(struct usb_transfer *transfer)
{
	struct usb_transfer *cur;
	struct timeval *timeout = &transfer->timeout;
	struct libusb_context *ctx = ITRANSFER_CTX(transfer);
	int r = 0;

	usb_mutex_lock(&ctx->flying_transfers_lock);

	/* if we have no other flying transfers, start the list with this one */
	if (list_empty(&ctx->flying_transfers)) {
		list_add(&transfer->list, &ctx->flying_transfers);
		goto out;
	}

	/* if we have infinite timeout, append to end of list */
	if (!timerisset(timeout)) {
		list_add_tail(&transfer->list, &ctx->flying_transfers);
		goto out;
	}

	/* otherwise, find appropriate place in list */
	list_for_each_entry(cur, &ctx->flying_transfers, list, struct usb_transfer) {
		/* find first timeout that occurs after the transfer in question */
		struct timeval *cur_tv = &cur->timeout;

		if (!timerisset(cur_tv) || timercmp(cur_tv, timeout, >)) {
			list_add_tail(&transfer->list, &cur->list);
			goto out;
		}
	}

	/* otherwise we need to be inserted at the end */
	list_add_tail(&transfer->list, &ctx->flying_transfers);
out:
	usb_mutex_unlock(&ctx->flying_transfers_lock);
}

struct libusb_transfer *_libusb_alloc_transfer(int iso_packets)
{
	size_t os_alloc_size = usb_backend->transfer_priv_size
		+ (usb_backend->add_iso_packet_size * iso_packets);
	size_t alloc_size = sizeof(struct usb_transfer)
		+ sizeof(struct libusb_transfer)
		+ (sizeof(struct libusb_iso_packet_descriptor) * iso_packets)
		+ os_alloc_size;
	struct usb_transfer *itransfer = malloc(alloc_size);
	if (!itransfer)
		return NULL;

	memset(itransfer, 0, alloc_size);
	itransfer->num_iso_packets = iso_packets;
	usb_mutex_init(&itransfer->lock, NULL);
	return USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
}


void libusb_free_transfer(struct libusb_transfer *transfer)
{
	struct usb_transfer *itransfer;
	if (!transfer)
		return;

	if (transfer->flags & LIBUSB_TRANSFER_FREE_BUFFER && transfer->buffer)
		free(transfer->buffer);

	itransfer = LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	usb_mutex_destroy(&itransfer->lock);
	free(itransfer);
}

int libusb_submit_transfer(struct libusb_transfer *transfer)
{
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	struct usb_transfer *itransfer =
		LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	int r;

	usb_mutex_lock(&itransfer->lock);
	itransfer->transferred = 0;
	itransfer->flags = 0;
	r = calculate_timeout(itransfer);
	if (r < 0) {
		r = LIBUSB_ERROR_OTHER;
		goto out;
	}

	add_to_flying_list(itransfer);
	r = usb_backend->submit_transfer(itransfer);
	if (r) {
		usb_mutex_lock(&ctx->flying_transfers_lock);
		list_del(&itransfer->list);
		usb_mutex_unlock(&ctx->flying_transfers_lock);
	}
out:
	usb_mutex_unlock(&itransfer->lock);
	return r;
}

int libusb_cancel_transfer(struct libusb_transfer *transfer)
{
	struct usb_transfer *itransfer =
		LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	int r;

	usb_dbg("");
	usb_mutex_lock(&itransfer->lock);
	r = usb_backend->cancel_transfer(itransfer);
	if (r < 0) {
		if (r != LIBUSB_ERROR_NOT_FOUND)
			usb_err(TRANSFER_CTX(transfer),
				"cancel transfer failed error %d", r);
		else
			usb_dbg("cancel transfer failed error %d", r);

		if (r == LIBUSB_ERROR_NO_DEVICE)
			itransfer->flags |= USBI_TRANSFER_DEVICE_DISAPPEARED;
	}

	itransfer->flags |= USBI_TRANSFER_CANCELLING;

	usb_mutex_unlock(&itransfer->lock);
	return r;
}

int usb_handle_transfer_completion(struct usb_transfer *itransfer,
	enum libusb_transfer_status status)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	uint8_t flags;
	int r = 0;

	usb_mutex_lock(&ctx->flying_transfers_lock);
	list_del(&itransfer->list);
	usb_mutex_unlock(&ctx->flying_transfers_lock);

	if (status == LIBUSB_TRANSFER_COMPLETED
			&& transfer->flags & LIBUSB_TRANSFER_SHORT_NOT_OK) {
		int rqlen = transfer->length;
		if (transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL)
			rqlen -= LIBUSB_CONTROL_SETUP_SIZE;
		if (rqlen != itransfer->transferred) {
			usb_dbg("interpreting short transfer as error");
			status = LIBUSB_TRANSFER_ERROR;
		}
	}

	flags = transfer->flags;
	transfer->status = status;
	transfer->actual_length = itransfer->transferred;
	usb_dbg("transfer %p has callback %p", transfer, transfer->callback);
	if (transfer->callback)
		transfer->callback(transfer);

	if (flags & LIBUSB_TRANSFER_FREE_TRANSFER)
		libusb_free_transfer(transfer);
	usb_mutex_lock(&ctx->event_waiters_lock);
	usb_cond_broadcast(&ctx->event_waiters_cond);
	usb_mutex_unlock(&ctx->event_waiters_lock);
	return 0;
}

int usb_handle_transfer_cancellation(struct usb_transfer *transfer)
{
	if (transfer->flags & USBI_TRANSFER_TIMED_OUT) {
		usb_dbg("detected timeout cancellation");
		return usb_handle_transfer_completion(transfer, LIBUSB_TRANSFER_TIMED_OUT);
	}

	return usb_handle_transfer_completion(transfer, LIBUSB_TRANSFER_CANCELLED);
}


void usb_handle_disconnect(struct libusb_device_handle *handle)
{
	struct usb_transfer *cur;
	struct usb_transfer *to_cancel;

	usb_dbg("device %d.%d",
		handle->dev->bus_number, handle->dev->device_address);

	while (1) {
		usb_mutex_lock(&HANDLE_CTX(handle)->flying_transfers_lock);
		to_cancel = NULL;
		list_for_each_entry(cur, &HANDLE_CTX(handle)->flying_transfers, list, struct usb_transfer)
			if (USBI_TRANSFER_TO_LIBUSB_TRANSFER(cur)->dev_handle == handle) {
				to_cancel = cur;
				break;
			}
		usb_mutex_unlock(&HANDLE_CTX(handle)->flying_transfers_lock);

		if (!to_cancel)
			break;

		usb_backend->clear_transfer_priv(to_cancel);
		usb_handle_transfer_completion(to_cancel, LIBUSB_TRANSFER_NO_DEVICE);
	}

}

