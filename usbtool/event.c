#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>

#include "common.h"
#include "libusb.h"

static int libusb_try_lock_events(libusb_context *ctx)
{
	int r;
	USBI_GET_CONTEXT(ctx);

	/* is someone else waiting to modify poll fds? if so, don't let this thread
	 * start event handling */
	usb_mutex_lock(&ctx->pollfd_modify_lock);
	r = ctx->pollfd_modify;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);
	if (r) {
		usb_dbg("someone else is modifying poll fds");
		return 1;
	}

	r = usb_mutex_trylock(&ctx->events_lock);
	if (r)
		return 1; /*获得锁失败,返回1*/

	ctx->event_handler_active = 1;
	return 0;
}

void libusb_lock_events(libusb_context *ctx)
{
	USBI_GET_CONTEXT(ctx);
	usb_mutex_lock(&ctx->events_lock);
	ctx->event_handler_active = 1;
}

void  libusb_unlock_events(libusb_context *ctx)
{
	USBI_GET_CONTEXT(ctx);
	ctx->event_handler_active = 0;
	usb_mutex_unlock(&ctx->events_lock);

	usb_mutex_lock(&ctx->event_waiters_lock);
	usb_cond_broadcast(&ctx->event_waiters_cond);
	usb_mutex_unlock(&ctx->event_waiters_lock);
}

static int libusb_event_handler_active(libusb_context *ctx)
{
	int r;
	USBI_GET_CONTEXT(ctx);

	usb_mutex_lock(&ctx->pollfd_modify_lock);
	r = ctx->pollfd_modify;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);
	if (r) {
		usb_dbg("someone else is modifying poll fds");
		return 1;
	}

	return ctx->event_handler_active;
}


static void libusb_lock_event_waiters(libusb_context *ctx)
{
	USBI_GET_CONTEXT(ctx);
	usb_mutex_lock(&ctx->event_waiters_lock);
}

static void libusb_unlock_event_waiters(libusb_context *ctx)
{
	USBI_GET_CONTEXT(ctx);
	usb_mutex_unlock(&ctx->event_waiters_lock);
}

static int libusb_wait_for_event(libusb_context *ctx, struct timeval *tv)
{
	struct timespec timeout;
	int r;

	USBI_GET_CONTEXT(ctx);
	if (tv == NULL) {
		usb_cond_wait(&ctx->event_waiters_cond, &ctx->event_waiters_lock);
		return 0;
	}

	r = usb_backend->clock_gettime(USBI_CLOCK_REALTIME, &timeout);
	if (r < 0) {
		usb_err(ctx, "failed to read realtime clock, error %d", errno);
		return LIBUSB_ERROR_OTHER;
	}

	timeout.tv_sec += tv->tv_sec;
	timeout.tv_nsec += tv->tv_usec * 1000;
	if (timeout.tv_nsec > 1000000000) {
		timeout.tv_nsec -= 1000000000;
		timeout.tv_sec++;
	}

	r = usb_cond_timedwait(&ctx->event_waiters_cond,
		&ctx->event_waiters_lock, &timeout);
	if (r == ETIMEDOUT)
		r = LIBUSB_ERROR_TIMEOUT; 

	return r;
}

int usb_add_pollfd(struct libusb_context *ctx, int fd, short events)
{
	struct usb_pollfd *pollfd = malloc(sizeof(*pollfd));
	if (pollfd == NULL)
		return LIBUSB_ERROR_NO_MEM;

	usb_dbg("add fd %d events %d", fd, events);
	pollfd->pollfd.fd = fd;
	pollfd->pollfd.events = events;
	usb_mutex_lock(&ctx->pollfds_lock);
	list_add_tail(&pollfd->list, &ctx->pollfds);
	usb_mutex_unlock(&ctx->pollfds_lock);

	if (ctx->fd_added_cb)
		ctx->fd_added_cb(fd, events, ctx->fd_cb_user_data);
	return 0;
}

void usb_remove_pollfd(struct libusb_context *ctx, int fd)
{
	struct usb_pollfd *pollfd;
	int found = 0;

	usb_dbg("remove fd %d", fd);
	usb_mutex_lock(&ctx->pollfds_lock);
	list_for_each_entry(pollfd, &ctx->pollfds, list, struct usb_pollfd)
		if (pollfd->pollfd.fd == fd) {
			found = 1;
			break;
		}

	if (!found) {
		usb_dbg("couldn't find fd %d to remove", fd);
		usb_mutex_unlock(&ctx->pollfds_lock);
		return;
	}

	list_del(&pollfd->list);
	usb_mutex_unlock(&ctx->pollfds_lock);
	free(pollfd);
	if (ctx->fd_removed_cb)
		ctx->fd_removed_cb(fd, ctx->fd_cb_user_data);
}

static void handle_timeout(struct usb_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	int r;

	itransfer->flags |= USBI_TRANSFER_TIMED_OUT;
	r = libusb_cancel_transfer(transfer);
	if (r < 0)
		usb_warn(TRANSFER_CTX(transfer),
			"async cancel failed %d errno=%d", r, errno);
}

static int handle_timeouts_locked(struct libusb_context *ctx)
{
	int r;
	struct timespec systime_ts;
	struct timeval systime;
	struct usb_transfer *transfer;

	if (list_empty(&ctx->flying_transfers))
		return 0;

	/* get current time */
	r = usb_backend->clock_gettime(USBI_CLOCK_MONOTONIC, &systime_ts);
	if (r < 0)
		return r;

	TIMESPEC_TO_TIMEVAL(&systime, &systime_ts);

	list_for_each_entry(transfer, &ctx->flying_transfers, list, struct usb_transfer) {
		struct timeval *cur_tv = &transfer->timeout;

		/* if we've reached transfers of infinite timeout, we're all done */
		if (!timerisset(cur_tv))
			return 0;

		/* ignore timeouts we've already handled */
		if (transfer->flags & (USBI_TRANSFER_TIMED_OUT | USBI_TRANSFER_OS_HANDLES_TIMEOUT))
			continue;

		/* if transfer has non-expired timeout, nothing more to do */
		if ((cur_tv->tv_sec > systime.tv_sec) ||
				(cur_tv->tv_sec == systime.tv_sec &&
					cur_tv->tv_usec > systime.tv_usec))
			return 0;

		/* otherwise, we've got an expired timeout to handle */
		handle_timeout(transfer);
	}
	return 0;
}

static int handle_timeouts(struct libusb_context *ctx)
{
	int r;
	USBI_GET_CONTEXT(ctx);
	usb_mutex_lock(&ctx->flying_transfers_lock);
	r = handle_timeouts_locked(ctx);
	usb_mutex_unlock(&ctx->flying_transfers_lock);
	return r;
}

static int handle_events(struct libusb_context *ctx, struct timeval *tv)
{
	int r;
	struct usb_pollfd *ipollfd;
	struct pollfd *fds;
	int i = 0;
	int timeout_ms;
	int nfds = 0;

	usb_mutex_lock(&ctx->pollfds_lock);
	list_for_each_entry(ipollfd, &ctx->pollfds, list, struct usb_pollfd)
		nfds++;

	/* TODO: malloc when number of fd's changes, not on every poll */
	fds = malloc(sizeof(*fds) * nfds);
	if (!fds) {
		usb_mutex_unlock(&ctx->pollfds_lock);
		return LIBUSB_ERROR_NO_MEM;
	}

	list_for_each_entry(ipollfd, &ctx->pollfds, list, struct usb_pollfd) {
		struct libusb_pollfd *pollfd = &ipollfd->pollfd;
		int fd = pollfd->fd;
		fds[i].fd = fd;
		fds[i].events = pollfd->events;
		fds[i].revents = 0;
		i++;
	}
	usb_mutex_unlock(&ctx->pollfds_lock);

	timeout_ms = (tv->tv_sec * 1000) + (tv->tv_usec / 1000);

	/* round up to next millisecond */
	if (tv->tv_usec % 1000)
		timeout_ms++;

	usb_dbg("poll() %d fds with timeout in %dms", nfds, timeout_ms);
	r = usb_poll(fds, nfds, timeout_ms);
	if (r == 0) {
		free(fds);
		usb_dbg("poll() timeout");
		return handle_timeouts(ctx);
	} else if (r == -1 && errno == EINTR) {
		free(fds);
		return LIBUSB_ERROR_INTERRUPTED;
	} else if (r < 0) {
		free(fds);
		usb_err(ctx, "poll failed %d err=%d\n", r, errno);
		return LIBUSB_ERROR_IO;
	}

	/* fd[0] is always the ctrl pipe */
	if (fds[0].revents) {
		/* another thread wanted to interrupt event handling, and it succeeded!
		 * handle any other events that cropped up at the same time, and
		 * simply return */
		usb_dbg("caught a fish on the control pipe");

		if (r == 1) {
			r = 0;
			goto handled;
		} else {
			/* prevent OS backend from trying to handle events on ctrl pipe */
			fds[0].revents = 0;
			r--;
		}
	}

	r = usb_backend->handle_events(ctx, fds, nfds, r);
	if (r)
		usb_err(ctx, "backend handle_events failed with error %d", r);

handled:
	free(fds);
	return r;
}

static int libusb_get_next_timeout(libusb_context *ctx,
	struct timeval *tv)
{
	struct usb_transfer *transfer;
	struct timespec cur_ts;
	struct timeval cur_tv;
	struct timeval *next_timeout;
	int r;
	int found = 0;

	USBI_GET_CONTEXT(ctx);
	usb_mutex_lock(&ctx->flying_transfers_lock);
	if (list_empty(&ctx->flying_transfers)) {
		usb_mutex_unlock(&ctx->flying_transfers_lock);
		usb_dbg("no URBs, no timeout!");
		return 0;
	}

	/* find next transfer which hasn't already been processed as timed out */
	list_for_each_entry(transfer, &ctx->flying_transfers, list, struct usb_transfer) {
		if (transfer->flags & (USBI_TRANSFER_TIMED_OUT | USBI_TRANSFER_OS_HANDLES_TIMEOUT))
			continue;

		/* no timeout for this transfer? */
		if (!timerisset(&transfer->timeout))
			continue;

		found = 1;
		break;
	}
	usb_mutex_unlock(&ctx->flying_transfers_lock);

	if (!found) {
		usb_dbg("no URB with timeout or all handled by OS; no timeout!");
		return 0;
	}

	next_timeout = &transfer->timeout;

	r = usb_backend->clock_gettime(USBI_CLOCK_MONOTONIC, &cur_ts);
	if (r < 0) {
		usb_err(ctx, "failed to read monotonic clock, errno=%d", errno);
		return LIBUSB_ERROR_OTHER;
	}
	TIMESPEC_TO_TIMEVAL(&cur_tv, &cur_ts);

	if (timercmp(&cur_tv, next_timeout, >)) {
		usb_dbg("first timeout already expired");
		timerclear(tv);
	} else {
		timersub(next_timeout, &cur_tv, tv);
		usb_dbg("next timeout in %d.%06ds", tv->tv_sec, tv->tv_usec);
	}

	return 1;
}

static int get_next_timeout(libusb_context *ctx, struct timeval *tv,
	struct timeval *out)
{
	struct timeval timeout;
	int r = libusb_get_next_timeout(ctx, &timeout);
	if (r) {
		/* whether timeout already expired? */
		if (!timerisset(&timeout))
			return LIBUSB_ERROR_TIMEOUT;

		/* choose the smallest of next URB timeout or user specified timeout */
		if (timercmp(&timeout, tv, <))
			*out = timeout;
		else
			*out = *tv;
	} else {
		*out = *tv;
	}
	return 0;
}


int libusb_handle_events_completed(libusb_context *ctx,
	int *completed)
{
	int r;
	struct timeval poll_timeout;
	struct timeval tv;
	tv.tv_sec = 60;
	tv.tv_usec = 0;

	USBI_GET_CONTEXT(ctx);
	r = get_next_timeout(ctx, &tv, &poll_timeout);
	if (r == LIBUSB_ERROR_TIMEOUT) {
		/* timeout already expired */
		return handle_timeouts(ctx);
	}

retry:
	if (libusb_try_lock_events(ctx) == 0) {
		if (completed == NULL || !*completed) {
			/* we obtained the event lock: do our own event handling */
			usb_dbg("doing our own event handling");
			r = handle_events(ctx, &poll_timeout);
		}
		libusb_unlock_events(ctx);
		return r;
	}

	/* another thread is doing event handling. wait for thread events that
	 * notify event completion. */
	libusb_lock_event_waiters(ctx);

	if (completed && *completed)
		goto already_done;

	if (!libusb_event_handler_active(ctx)) {
		/* we hit a race: whoever was event handling earlier finished in the
		 * time it took us to reach this point. try the cycle again. */
		libusb_unlock_event_waiters(ctx);
		usb_dbg("event handler was active but went away, retrying");
		goto retry;
	}

	usb_dbg("another thread is doing event handling");
	r = libusb_wait_for_event(ctx, &poll_timeout);

already_done:
	libusb_unlock_event_waiters(ctx);

	if (r < 0)
		return r;
	else if (r == LIBUSB_ERROR_TIMEOUT)
		return handle_timeouts(ctx);
	else
		return 0;
}
