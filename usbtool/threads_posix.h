#ifndef LIBUSB_THREADS_POSIX_H
#define LIBUSB_THREADS_POSIX_H

#include <pthread.h>

#define usb_mutex_static_t		pthread_mutex_t
#define USBI_MUTEX_INITIALIZER		PTHREAD_MUTEX_INITIALIZER
#define usb_mutex_static_lock		pthread_mutex_lock
#define usb_mutex_static_unlock	pthread_mutex_unlock

#define usb_mutex_t			pthread_mutex_t
#define usb_mutex_init			pthread_mutex_init
#define usb_mutex_lock			pthread_mutex_lock
#define usb_mutex_unlock		pthread_mutex_unlock
#define usb_mutex_trylock		pthread_mutex_trylock
#define usb_mutex_destroy		pthread_mutex_destroy

#define usb_cond_t			pthread_cond_t
#define usb_cond_init			pthread_cond_init
#define usb_cond_wait			pthread_cond_wait
#define usb_cond_timedwait		pthread_cond_timedwait
#define usb_cond_broadcast		pthread_cond_broadcast
#define usb_cond_destroy		pthread_cond_destroy
#define usb_cond_signal		pthread_cond_signal

extern int usb_mutex_init_recursive(pthread_mutex_t *mutex, pthread_mutexattr_t *attr);

#endif /* LIBUSB_THREADS_POSIX_H */
