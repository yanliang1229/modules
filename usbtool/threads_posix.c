#include "threads_posix.h"

int usb_mutex_init_recursive(pthread_mutex_t *mutex, pthread_mutexattr_t *attr)
{
	int err;
	pthread_mutexattr_t stack_attr;
	if (!attr) {
		attr = &stack_attr;
		err = pthread_mutexattr_init(&stack_attr);
		if (err != 0)
			return err;
	}

	err = pthread_mutexattr_settype(attr, PTHREAD_MUTEX_RECURSIVE);
	if (err != 0)
		goto finish;

	err = pthread_mutex_init(mutex, attr);

finish:
	if (attr == &stack_attr)
		pthread_mutexattr_destroy(&stack_attr);

	return err;
}
