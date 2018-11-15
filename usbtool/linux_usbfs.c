#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "common.h"
#include "linux_usbfs.h"

static const char *usbfs_path = NULL;
static int usbdev_names = 0;
static int supports_flag_bulk_continuation = -1;
static int supports_flag_zero_packet = -1;
static int sysfs_can_relate_devices = 0;
static int sysfs_has_descriptors = 0;

typedef struct linux_device_priv {
	char *sysfs_dir;
	unsigned char *dev_descriptor;
	unsigned char *config_descriptor;
}linux_device_priv;

typedef struct linux_device_handle_priv {
	int fd;
}linux_device_handle_priv;

enum reap_action {
	NORMAL = 0,
	SUBMIT_FAILED,
	CANCELLED,
	COMPLETED_EARLY,
	ERROR,
};

struct linux_transfer_priv {
	union {
		struct usbfs_urb *urbs;
		struct usbfs_urb **iso_urbs;
	};

	enum reap_action reap_action;
	int num_urbs;
	unsigned int num_retired;
	enum libusb_transfer_status reap_status;
	int iso_packet_offset;
};

static void _get_usbfs_path(libusb_device *dev, char *path)
{
	if (usbdev_names)
		snprintf(path, PATH_MAX, "%s/usbdev%d.%d",
			usbfs_path, dev->bus_number, dev->device_address);
	else
		snprintf(path, PATH_MAX, "%s/%03d/%03d",
			usbfs_path, dev->bus_number, dev->device_address);
}

static linux_device_priv *_device_priv(libusb_device *dev)
{
	return (linux_device_priv *) dev->os_priv;
}

static linux_device_handle_priv *_device_handle_priv(libusb_device_handle *handle)
{
	return (linux_device_handle_priv *) handle->os_priv;
}

static int _is_usbdev_entry(struct dirent *entry, int *bus_p, int *dev_p)
{
	int busnum, devnum;

	if (sscanf(entry->d_name, "usbdev%d.%d", &busnum, &devnum) != 2)
		return 0;

	usb_dbg("found: %s", entry->d_name);
	if (bus_p != NULL)
		*bus_p = busnum;
	if (dev_p != NULL)
		*dev_p = devnum;
	return 1;
}

static int check_usb_vfs(const char *dirname)
{
	DIR *dir;
	struct dirent *entry;
	int found = 0;

	dir = opendir(dirname);
	if (!dir)
		return 0;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.' ||entry->d_name[1] == '.' )
			continue;

		found = 1;
		break;
	}

	closedir(dir);
	return found;
}

static const char *find_usbfs_path(void)
{
	const char *path = "/dev/bus/usb";
	const char *ret = NULL;

	if (check_usb_vfs(path)) {
		ret = path;
	} else {
		path = "/proc/bus/usb";
		if (check_usb_vfs(path))
			ret = path;
	}

	if (ret == NULL) {
		struct dirent *entry;
		DIR *dir;

		path = "/dev";
		dir = opendir(path);
		if (dir != NULL) {
			while ((entry = readdir(dir)) != NULL) {
				if (_is_usbdev_entry(entry, NULL, NULL)) {
					ret = path;
					usbdev_names = 1;
					break;
				}
			}
			closedir(dir);
		}
	}

	if (ret != NULL)
		usb_dbg("found usbfs at %s", ret);

	return ret;
}

static int kernel_version_ge(int major, int minor, int sublevel)
{
	struct utsname uts;
	int atoms, kmajor, kminor, ksublevel;

	if (uname(&uts) < 0)
		return -1;
	atoms = sscanf(uts.release, "%d.%d.%d", &kmajor, &kminor, &ksublevel);
	if (atoms < 1)
		return -1;

	if (kmajor > major)
		return 1;
	if (kmajor < major)
		return 0;

	/* kmajor == major */
	if (atoms < 2)
		return 0 == minor && 0 == sublevel;
	if (kminor > minor)
		return 1;
	if (kminor < minor)
		return 0;

	/* kminor == minor */
	if (atoms < 3)
		return 0 == sublevel;

	return ksublevel >= sublevel;
}

static int sysfs_has_file(const char *dirname, const char *filename)
{
	struct stat statbuf;
	char path[PATH_MAX];
	int r;

	snprintf(path, PATH_MAX, "%s/%s/%s", SYSFS_DEVICE_PATH, dirname, filename);
	r = stat(path, &statbuf);
	if (r == 0 && S_ISREG(statbuf.st_mode))
		return 1;

	return 0;
}

static int usb_init(struct libusb_context *ctx)
{
	struct stat statbuf;
	int r;

	usbfs_path = find_usbfs_path();
	if (!usbfs_path) {
		usb_err(ctx, "could not find usbfs");
		return LIBUSB_ERROR_OTHER;
	}

	if (supports_flag_bulk_continuation == -1) {
		/* bulk continuation URB flag available from Linux 2.6.32 */
		supports_flag_bulk_continuation = kernel_version_ge(2,6,32);
		if (supports_flag_bulk_continuation == -1) {
			usb_err(ctx, "error checking for bulk continuation support");
			return LIBUSB_ERROR_OTHER;
		}
	}

	if (supports_flag_bulk_continuation)
		usb_dbg("bulk continuation flag supported");

	if (supports_flag_zero_packet == -1) {
		/* zero length packet URB flag fixed since Linux 2.6.31 */
		supports_flag_zero_packet = kernel_version_ge(2,6,31);
		if (-1 == supports_flag_zero_packet) {
			usb_err(ctx, "error checking for zero length packet support");
			return LIBUSB_ERROR_OTHER;
		}
	}

	if (supports_flag_zero_packet)
		usb_dbg("zero length packet flag supported");

	r = stat(SYSFS_DEVICE_PATH, &statbuf);
	if (r == 0 && S_ISDIR(statbuf.st_mode)) {
		DIR *devices = opendir(SYSFS_DEVICE_PATH);
		struct dirent *entry;

		usb_dbg("found usb devices in sysfs");

		if (!devices) {
			usb_err(ctx, "opendir devices failed errno=%d", errno);
			return LIBUSB_ERROR_IO;
		}

		while ((entry = readdir(devices))) {
			int has_busnum=0, has_devnum=0, has_descriptors=0;
			int has_configuration_value=0;

			/* Only check the usbN directories. */
			if (strncmp(entry->d_name, "usb", 3) != 0)
				continue;

			/* Check for the files libusb needs from sysfs. */
			has_busnum = sysfs_has_file(entry->d_name, "busnum");
			has_devnum = sysfs_has_file(entry->d_name, "devnum");
			has_descriptors = sysfs_has_file(entry->d_name, "descriptors");
			has_configuration_value = sysfs_has_file(entry->d_name, "bConfigurationValue");

			if (has_busnum && has_devnum && has_configuration_value)
				sysfs_can_relate_devices = 1;
			if (has_descriptors)
				sysfs_has_descriptors = 1;

			if (sysfs_has_descriptors && sysfs_can_relate_devices)
				break;
		}
		closedir(devices);

		if (!sysfs_can_relate_devices)
			sysfs_has_descriptors = 0;
	} else {
		usb_dbg("sysfs usb info not available");
		sysfs_has_descriptors = 0;
		sysfs_can_relate_devices = 0;
	}

	return 0;
}

static int usbfs_get_device_descriptor(struct libusb_device *dev,
	unsigned char *buffer)
{
	struct linux_device_priv *priv = _device_priv(dev);

	/* return cached copy */
	memcpy(buffer, priv->dev_descriptor, DEVICE_DESC_LENGTH);
	return 0;
}

static int _open_sysfs_attr(struct libusb_device *dev, const char *attr)
{
	struct linux_device_priv *priv = _device_priv(dev);
	char filename[PATH_MAX];
	int fd;

	snprintf(filename, PATH_MAX, "%s/%s/%s",
		SYSFS_DEVICE_PATH, priv->sysfs_dir, attr);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		usb_err(DEVICE_CTX(dev),
			"open %s failed ret=%d errno=%d", filename, fd, errno);
		return LIBUSB_ERROR_IO;
	}

	return fd;
}

static int __read_sysfs_attr(struct libusb_context *ctx,
	const char *devname, const char *attr)
{
	char filename[PATH_MAX];
	FILE *f;
	int r, value;

	snprintf(filename, PATH_MAX, "%s/%s/%s", SYSFS_DEVICE_PATH,
		 devname, attr);
	f = fopen(filename, "r");
	if (f == NULL) {
		if (errno == ENOENT) {
			return LIBUSB_ERROR_NO_DEVICE;
		}
		usb_err(ctx, "open %s failed errno=%d", filename, errno);
		return LIBUSB_ERROR_IO;
	}

	r = fscanf(f, "%d", &value);
	fclose(f);
	if (r != 1) {
		usb_err(ctx, "fscanf %s returned %d, errno=%d", attr, r, errno);
		return LIBUSB_ERROR_NO_DEVICE; /* For unplug race (trac #70) */
	}
	if (value < 0) {
		usb_err(ctx, "%s contains a negative value", filename);
		return LIBUSB_ERROR_IO;
	}

	return value;
}

static int sysfs_get_device_descriptor(struct libusb_device *dev,
	unsigned char *buffer)
{
	int fd;
	ssize_t r;


	fd = _open_sysfs_attr(dev, "descriptors");
	if (fd < 0)
		return fd;

	r = read(fd, buffer, DEVICE_DESC_LENGTH);;
	close(fd);
	if (r < 0) {
		usb_err(DEVICE_CTX(dev), "read failed, ret=%d errno=%d", fd, errno);
		return LIBUSB_ERROR_IO;
	} else if (r < DEVICE_DESC_LENGTH) {
		usb_err(DEVICE_CTX(dev), "short read %d/%d", r, DEVICE_DESC_LENGTH);
		return LIBUSB_ERROR_IO;
	}

	return 0;
}

static int usb_get_device_descriptor(struct libusb_device *dev,
	unsigned char *buffer, int *host_endian)
{
	if (sysfs_has_descriptors) {
		return sysfs_get_device_descriptor(dev, buffer);
	} else {
		*host_endian = 1;
		return usbfs_get_device_descriptor(dev, buffer);
	}
}

static int usbfs_get_active_config_descriptor(struct libusb_device *dev,
	unsigned char *buffer, size_t len)
{
	struct linux_device_priv *priv = _device_priv(dev);
	if (!priv->config_descriptor)
		return LIBUSB_ERROR_NOT_FOUND; /* device is unconfigured */

	memcpy(buffer, priv->config_descriptor, len);
	return 0;
}

static int sysfs_get_active_config(struct libusb_device *dev, int *config)
{
	char *endptr;
	char tmp[4] = {0, 0, 0, 0};
	long num;
	int fd;
	ssize_t r;

	fd = _open_sysfs_attr(dev, "bConfigurationValue");
	if (fd < 0)
		return fd;

	r = read(fd, tmp, sizeof(tmp));
	close(fd);
	if (r < 0) {
		usb_err(DEVICE_CTX(dev), 
			"read bConfigurationValue failed ret=%d errno=%d", r, errno);
		return LIBUSB_ERROR_IO;
	} else if (r == 0) {
		usb_dbg("device unconfigured");
		*config = -1;
		return 0;
	}

	if (tmp[sizeof(tmp) - 1] != 0) {
		usb_err(DEVICE_CTX(dev), "not null-terminated?");
		return LIBUSB_ERROR_IO;
	} else if (tmp[0] == 0) {
		usb_err(DEVICE_CTX(dev), "no configuration value?");
		return LIBUSB_ERROR_IO;
	}

	num = strtol(tmp, &endptr, 10);
	if (endptr == tmp) {
		usb_err(DEVICE_CTX(dev), "error converting '%s' to integer", tmp);
		return LIBUSB_ERROR_IO;
	}

	*config = (int) num;
	return 0;
}

static int seek_to_next_config(struct libusb_context *ctx, int fd,
	int host_endian)
{
	struct libusb_config_descriptor config;
	unsigned char tmp[6];
	off_t off;
	ssize_t r;

	/* read first 6 bytes of descriptor */
	r = read(fd, tmp, sizeof(tmp));
	if (r < 0) {
		usb_err(ctx, "read failed ret=%d errno=%d", r, errno);
		return LIBUSB_ERROR_IO;
	} else if (r < sizeof(tmp)) {
		usb_err(ctx, "short descriptor read %d/%d", r, sizeof(tmp));
		return LIBUSB_ERROR_IO;
	}

	usb_parse_descriptor(tmp, "bbwbb", &config, host_endian);
	/* seek forward to end of config */
	off = lseek(fd, config.wTotalLength - sizeof(tmp), SEEK_CUR);
	if (off < 0) {
		usb_err(ctx, "seek failed ret=%d errno=%d", off, errno);
		return LIBUSB_ERROR_IO;
	}

	return 0;
}

static int sysfs_get_active_config_descriptor(struct libusb_device *dev,
	unsigned char *buffer, size_t len)
{
	int fd;
	ssize_t r;
	off_t off;
	int to_copy;
	int cfg;
	unsigned char tmp[6];
	struct stat statstuff;
	struct libusb_config_descriptor config;

	r = sysfs_get_active_config(dev, &cfg);
	if (r < 0)
		return r;
	if (cfg == -1)
		return LIBUSB_ERROR_NOT_FOUND;

	usb_dbg("active configuration %d", cfg);

	fd = _open_sysfs_attr(dev, "descriptors");
	if (fd < 0)
		return fd;
	r = fstat(fd, &statstuff);
	if (r < 0)
		return r;
	if (statstuff.st_size <= DEVICE_DESC_LENGTH) {
		close(fd);
		return LIBUSB_ERROR_NOT_FOUND;
	}

	off = lseek(fd, DEVICE_DESC_LENGTH, SEEK_SET);
	if (off < 0) {
		usb_err(DEVICE_CTX(dev), "seek failed, ret=%d errno=%d", off, errno);
		close(fd);
		return LIBUSB_ERROR_IO;
	}

	while (1) {
		r = read(fd, &config, sizeof(config));
		if (r < 0) {
			usb_err(DEVICE_CTX(dev), "read failed, ret=%d errno=%d",
				fd, errno);
			return LIBUSB_ERROR_IO;
		} else if (r < sizeof(config)) {
			usb_err(DEVICE_CTX(dev), "short read %d/%d", r, sizeof(tmp));
			return LIBUSB_ERROR_IO;
		}

		/* check bConfigurationValue */
		if (config.bConfigurationValue == cfg)
			break;

		/* try the next descriptor */
		off = lseek(fd, 0 - sizeof(config), SEEK_CUR);
		if (off < 0)
			return LIBUSB_ERROR_IO;

		r = seek_to_next_config(DEVICE_CTX(dev), fd, 0);
		if (r < 0)
			return r;
	}

	if (len > config.bLength)
		len = config.bLength;
	r = read(fd, buffer + sizeof(tmp), len - sizeof(tmp));
	if (r < 0) {
		usb_err(DEVICE_CTX(dev), "read failed, ret=%d errno=%d",
			fd, errno);
		r = LIBUSB_ERROR_IO;
	} else if (r == 0) {
		usb_dbg("device is unconfigured");
		r = LIBUSB_ERROR_NOT_FOUND;
	} else if (r < len ) {
		usb_err(DEVICE_CTX(dev), "short read %d/%d", r, len);
		r = LIBUSB_ERROR_IO;
	} else
		r = 0;
	close(fd);
	return r;
}

static int usb_get_active_config_descriptor(struct libusb_device *dev,
	unsigned char *buffer, size_t len, int *host_endian)
{
	if (sysfs_has_descriptors) {
		return sysfs_get_active_config_descriptor(dev, buffer, len);
	} else {
		return usbfs_get_active_config_descriptor(dev, buffer, len);
	}
}

static int get_config_descriptor(struct libusb_context *ctx, int fd,
	uint8_t index, unsigned char *buffer, size_t len)
{
	off_t off;
	ssize_t r;

	off = lseek(fd, DEVICE_DESC_LENGTH, SEEK_SET);
	if (off < 0) {
		usb_err(ctx, "seek failed ret=%d errno=%d", off, errno);
		return LIBUSB_ERROR_IO;
	}

	while (index > 0) {
		r = seek_to_next_config(ctx, fd, 1);
		if (r < 0)
			return r;
		index--;
	}

	/* read the rest of the descriptor */
	r = read(fd, buffer, len);
	if (r < 0) {
		usb_err(ctx, "read failed ret=%d errno=%d", r, errno);
		return LIBUSB_ERROR_IO;
	} else if (r < len) {
		usb_err(ctx, "short output read %d/%d", r, len);
		return LIBUSB_ERROR_IO;
	}

	return 0;
}

static int usb_get_config_descriptor(struct libusb_device *dev,
	uint8_t index, unsigned char *buffer, size_t len, int *host_endian)
{
	char filename[PATH_MAX];
	int fd;
	int r;

	_get_usbfs_path(dev, filename);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		usb_err(DEVICE_CTX(dev),
			"open '%s' failed, ret=%d errno=%d", filename, fd, errno);
		return LIBUSB_ERROR_IO;
	}

	r = get_config_descriptor(DEVICE_CTX(dev), fd, index, buffer, len);
	close(fd);
	return r;
}

static int cache_active_config(struct libusb_device *dev, int fd,
	int active_config)
{
	struct linux_device_priv *priv = _device_priv(dev);
	struct libusb_config_descriptor config;
	unsigned char tmp[8];
	unsigned char *buf;
	int idx;
	int r;

	if (active_config == -1) {
		idx = 0;
	} else {
		r = usb_get_config_index_by_value(dev, active_config, &idx);
		if (r < 0)
			return r;
		if (idx == -1)
			return LIBUSB_ERROR_NOT_FOUND;
	}

	r = get_config_descriptor(DEVICE_CTX(dev), fd, idx, tmp, sizeof(tmp));
	if (r < 0) {
		usb_err(DEVICE_CTX(dev), "first read error %d", r);
		return r;
	}

	usb_parse_descriptor(tmp, "bbw", &config, 0);
	buf = malloc(config.wTotalLength);
	if (!buf)
		return LIBUSB_ERROR_NO_MEM;

	r = get_config_descriptor(DEVICE_CTX(dev), fd, idx, buf,
		config.wTotalLength);
	if (r < 0) {
		free(buf);
		return r;
	}

	if (priv->config_descriptor)
		free(priv->config_descriptor);
	priv->config_descriptor = buf;
	return 0;
}

static int usb_ioctl(struct libusb_device_handle *handle, int cmd, void *data)
{
	int fd = _device_handle_priv(handle)->fd;
	int r = ioctl(fd, cmd, data);
	if (r) {
		if (errno == ENOENT)
			return LIBUSB_ERROR_NOT_FOUND;
		else if (errno == EBUSY)
			return LIBUSB_ERROR_BUSY;
		else if (errno == ENODEV)
			return LIBUSB_ERROR_NO_DEVICE;
		return LIBUSB_ERROR_OTHER;
	}
	return 0;

}
/* send a control message to retrieve active configuration */
static int usbfs_get_active_config(struct libusb_device *dev, int fd)
{
	unsigned char active_config = 0;
	int r;

	struct usbfs_ctrltransfer ctrl = {
		.bmRequestType = LIBUSB_ENDPOINT_IN,
		.bRequest = LIBUSB_REQUEST_GET_CONFIGURATION,
		.wValue = 0,
		.wIndex = 0,
		.wLength = 1,
		.timeout = 1000,
		.data = &active_config
	};

	r = ioctl(fd, IOCTL_USBFS_CONTROL, &ctrl);
	if (r < 0) {
		if (errno == ENODEV)
			return LIBUSB_ERROR_NO_DEVICE;

		usb_warn(DEVICE_CTX(dev),
			"get_configuration failed ret=%d errno=%d", r, errno);
		return LIBUSB_ERROR_IO;
	}

	return active_config;
}

static int initialize_device(struct libusb_device *dev, uint8_t busnum,
	uint8_t devaddr, const char *sysfs_dir)
{
	struct linux_device_priv *priv = _device_priv(dev);
	unsigned char *dev_buf;
	char path[PATH_MAX];
	int fd, speed;
	int active_config = 0;
	int device_configured = 1;
	ssize_t r;

	dev->bus_number = busnum;
	dev->device_address = devaddr;

	if (sysfs_dir) {
		priv->sysfs_dir = malloc(strlen(sysfs_dir) + 1);
		if (!priv->sysfs_dir)
			return LIBUSB_ERROR_NO_MEM;
		strcpy(priv->sysfs_dir, sysfs_dir);
		speed = __read_sysfs_attr(DEVICE_CTX(dev), sysfs_dir, "speed");
		if (speed >= 0) {
			switch (speed) {
			case     1: dev->speed = LIBUSB_SPEED_LOW; break;
			case    12: dev->speed = LIBUSB_SPEED_FULL; break;
			case   480: dev->speed = LIBUSB_SPEED_HIGH; break;
			case  5000: dev->speed = LIBUSB_SPEED_SUPER; break;
			default:
				usb_warn(DEVICE_CTX(dev), "Unknown device speed: %d Mbps", speed);
			}
		}
	}

	if (sysfs_has_descriptors)
		return 0;

	priv->dev_descriptor = NULL;
	priv->config_descriptor = NULL;

	if (sysfs_can_relate_devices) {
		int tmp = sysfs_get_active_config(dev, &active_config);
		if (tmp < 0)
			return tmp;
		if (active_config == -1)
			device_configured = 0;
	}

	_get_usbfs_path(dev, path);
	fd = open(path, O_RDWR);
	if (fd < 0 && errno == EACCES) {
		fd = open(path, O_RDONLY);
		active_config = -1;
	}

	if (fd < 0) {
		usb_err(DEVICE_CTX(dev), "open failed, ret=%d errno=%d", fd, errno);
		return LIBUSB_ERROR_IO;
	}

	if (!sysfs_can_relate_devices) {
		if (active_config == -1) {
			usb_warn(DEVICE_CTX(dev), "access to %s is read-only; cannot "
				"determine active configuration descriptor", path);
		} else {
			active_config = usbfs_get_active_config(dev, fd);
			if (active_config == LIBUSB_ERROR_IO) {
				usb_warn(DEVICE_CTX(dev), "couldn't query active "
					"configuration, assumung unconfigured");
				device_configured = 0;
			} else if (active_config < 0) {
				close(fd);
				return active_config;
			} else if (active_config == 0) {
				usb_dbg("active cfg 0? assuming unconfigured device");
				device_configured = 0;
			}
		}
	}

	dev_buf = malloc(DEVICE_DESC_LENGTH);
	if (!dev_buf) {
		close(fd);
		return LIBUSB_ERROR_NO_MEM;
	}

	r = read(fd, dev_buf, DEVICE_DESC_LENGTH);
	if (r < 0) {
		usb_err(DEVICE_CTX(dev),
			"read descriptor failed ret=%d errno=%d", fd, errno);
		free(dev_buf);
		close(fd);
		return LIBUSB_ERROR_IO;
	} else if (r < DEVICE_DESC_LENGTH) {
		usb_err(DEVICE_CTX(dev), "short descriptor read (%d)", r);
		free(dev_buf);
		close(fd);
		return LIBUSB_ERROR_IO;
	}

	dev->num_configurations = dev_buf[DEVICE_DESC_LENGTH - 1];

	if (device_configured) {
		r = cache_active_config(dev, fd, active_config);
		if (r < 0) {
			close(fd);
			free(dev_buf);
			return r;
		}
	}

	close(fd);
	priv->dev_descriptor = dev_buf;
	return 0;
}

static int enumerate_device(struct libusb_context *ctx,
	struct discovered_devs **_discdevs, uint8_t busnum, uint8_t devaddr,
	const char *sysfs_dir)
{
	struct discovered_devs *discdevs;
	unsigned long session_id;
	int need_unref = 0;
	struct libusb_device *dev;
	int r = 0;

	/* FIXME: session ID is not guaranteed unique as addresses can wrap and
	 * will be reused. instead we should add a simple sysfs attribute with
	 * a session ID. */
	session_id = busnum << 8 | devaddr;
	usb_dbg("busnum %d devaddr %d session_id %ld", busnum, devaddr,
		session_id);

	dev = usb_get_device_by_session_id(ctx, session_id);
	if (dev) {
		usb_dbg("using existing device for %d/%d (session %ld)",
			busnum, devaddr, session_id);
	} else {
		usb_dbg("allocating new device for %d/%d (session %ld)",
			busnum, devaddr, session_id);
		dev = usb_alloc_device(ctx, session_id);
		if (!dev)
			return LIBUSB_ERROR_NO_MEM;
		need_unref = 1;
		r = initialize_device(dev, busnum, devaddr, sysfs_dir);
		if (r < 0)
			goto out;
		r = usb_sanitize_device(dev);
		if (r < 0)
			goto out;
	}

	discdevs = discovered_devs_append(*_discdevs, dev);
	if (!discdevs)
		r = LIBUSB_ERROR_NO_MEM;
	else
		*_discdevs = discdevs;

out:
	if (need_unref)
		libusb_unref_device(dev);
	return r;
}

static int usbfs_scan_busdir(struct libusb_context *ctx,
	struct discovered_devs **_discdevs, uint8_t busnum)
{
	DIR *dir;
	char dirpath[PATH_MAX];
	struct dirent *entry;
	struct discovered_devs *discdevs = *_discdevs;
	int r = LIBUSB_ERROR_IO;

	snprintf(dirpath, PATH_MAX, "%s/%03d", usbfs_path, busnum);
	usb_dbg("%s", dirpath);
	dir = opendir(dirpath);
	if (!dir) {
		usb_err(ctx, "opendir '%s' failed, errno=%d", dirpath, errno);
		/* FIXME: should handle valid race conditions like hub unplugged
		 * during directory iteration - this is not an error */
		return r;
	}

	while ((entry = readdir(dir))) {
		int devaddr;

		if (entry->d_name[0] == '.')
			continue;

		devaddr = atoi(entry->d_name);
		if (devaddr == 0) {
			usb_dbg("unknown dir entry %s", entry->d_name);
			continue;
		}

		if (enumerate_device(ctx, &discdevs, busnum, (uint8_t) devaddr, NULL)) {
			usb_dbg("failed to enumerate dir entry %s", entry->d_name);
			continue;
		}

		r = 0;
	}

	if (!r)
		*_discdevs = discdevs;
	closedir(dir);
	return r;
}

static int usbfs_get_device_list(struct libusb_context *ctx,
	struct discovered_devs **_discdevs)
{
	struct dirent *entry;
	DIR *buses = opendir(usbfs_path);
	struct discovered_devs *discdevs = *_discdevs;
	int r = 0;

	if (!buses) {
		usb_err(ctx, "opendir buses failed errno=%d", errno);
		return LIBUSB_ERROR_IO;
	}

	while ((entry = readdir(buses))) {
		struct discovered_devs *discdevs_new = discdevs;
		int busnum;

		if (entry->d_name[0] == '.')
			continue;

		if (usbdev_names) {
			int devaddr;
			if (!_is_usbdev_entry(entry, &busnum, &devaddr))
				continue;

			r = enumerate_device(ctx, &discdevs_new, busnum,
				(uint8_t) devaddr, NULL);
			if (r < 0) {
				usb_dbg("failed to enumerate dir entry %s", entry->d_name);
				continue;
			}
		} else {
			busnum = atoi(entry->d_name);
			if (busnum == 0) {
				usb_dbg("unknown dir entry %s", entry->d_name);
				continue;
			}

			r = usbfs_scan_busdir(ctx, &discdevs_new, busnum);
			if (r < 0)
				goto out;
		}
		discdevs = discdevs_new;
	}

out:
	closedir(buses);
	*_discdevs = discdevs;
	return r;

}

static int sysfs_scan_device(struct libusb_context *ctx,
	struct discovered_devs **_discdevs, const char *devname)
{
	int busnum;
	int devaddr;

	usb_dbg("scan %s", devname);

	busnum = __read_sysfs_attr(ctx, devname, "busnum");
	if (busnum < 0)
		return busnum;

	devaddr = __read_sysfs_attr(ctx, devname, "devnum");
	if (devaddr < 0)
		return devaddr;

	usb_dbg("bus=%d dev=%d", busnum, devaddr);
	if (busnum > 255 || devaddr > 255)
		return LIBUSB_ERROR_INVALID_PARAM;

	return enumerate_device(ctx, _discdevs, busnum & 0xff, devaddr & 0xff,
		devname);
}

static int sysfs_get_device_list(struct libusb_context *ctx,
	struct discovered_devs **_discdevs)
{
	struct discovered_devs *discdevs = *_discdevs;
	DIR *devices = opendir(SYSFS_DEVICE_PATH);
	struct dirent *entry;
	int r = LIBUSB_ERROR_IO;

	if (!devices) {
		usb_err(ctx, "opendir devices failed errno=%d", errno);
		return r;
	}

	while ((entry = readdir(devices))) {
		struct discovered_devs *discdevs_new = discdevs;

		if ((!isdigit(entry->d_name[0]) && strncmp(entry->d_name, "usb", 3))
				|| strchr(entry->d_name, ':'))
			continue;

		if (sysfs_scan_device(ctx, &discdevs_new, entry->d_name)) {
			usb_dbg("failed to enumerate dir entry %s", entry->d_name);
			continue;
		}

		r = 0;
		discdevs = discdevs_new;
	}

	if (!r)
		*_discdevs = discdevs;
	closedir(devices);
	return r;
}

static int usb_get_device_list(struct libusb_context *ctx,
	struct discovered_devs **_discdevs)
{
	if (sysfs_can_relate_devices != 0)
		return sysfs_get_device_list(ctx, _discdevs);
	else
		return usbfs_get_device_list(ctx, _discdevs);
}

static int usbdev_open(struct libusb_device_handle *handle)
{
	struct linux_device_handle_priv *hpriv = _device_handle_priv(handle);
	char filename[PATH_MAX];

	_get_usbfs_path(handle->dev, filename);
	usb_dbg("opening %s", filename);
	hpriv->fd = open(filename, O_RDWR);
	if (hpriv->fd < 0) {
		if (errno == EACCES) {
			usb_err(HANDLE_CTX(handle), "libusb couldn't open USB device %s: "
				"Permission denied.", filename);
			usb_err(HANDLE_CTX(handle),
				"libusb requires write access to USB device nodes.");
			return LIBUSB_ERROR_ACCESS;
		} else if (errno == ENOENT) {
			usb_err(HANDLE_CTX(handle), "libusb couldn't open USB device %s: "
				"No such file or directory.", filename);
			return LIBUSB_ERROR_NO_DEVICE;
		} else {
			usb_err(HANDLE_CTX(handle),
				"open failed, code %d errno %d", hpriv->fd, errno);
			return LIBUSB_ERROR_IO;
		}
	}

	return usb_add_pollfd(HANDLE_CTX(handle), hpriv->fd, POLLOUT);
}

static void usbdev_close(struct libusb_device_handle *dev_handle)
{
	int fd = _device_handle_priv(dev_handle)->fd;
	usb_remove_pollfd(HANDLE_CTX(dev_handle), fd);
	close(fd);
}

static int usb_get_configuration(struct libusb_device_handle *handle,
	int *config)
{
	int r;
	if (sysfs_can_relate_devices != 1)
		return LIBUSB_ERROR_NOT_SUPPORTED;

	r = sysfs_get_active_config(handle->dev, config);
	if (r < 0)
		return r;

	if (*config == -1) {
		usb_err(HANDLE_CTX(handle), "device unconfigured");
		*config = 0;
	}

	return 0;
}


static int usb_set_configuration(struct libusb_device_handle *handle, int config)
{
	struct linux_device_priv *priv = _device_priv(handle->dev);
	int fd = _device_handle_priv(handle)->fd;
	int r = usb_ioctl(handle, IOCTL_USBFS_SETCONFIG , &config);
	if (r)
		return r; 

	if (!sysfs_has_descriptors) {
		/* update our cached active config descriptor */
		if (config == -1) {
			if (priv->config_descriptor) {
				free(priv->config_descriptor);
				priv->config_descriptor = NULL;
			}
		} else {
			r = cache_active_config(handle->dev, fd, config);
			if (r < 0)
				usb_warn(HANDLE_CTX(handle),
					"failed to update cached config descriptor, error %d", r);
		}
	}

	return 0;
}

static int usb_claim_interface(struct libusb_device_handle *handle, int iface)
{
	return usb_ioctl(handle, IOCTL_USBFS_CLAIMINTF, &iface);
}

static int usb_release_interface(struct libusb_device_handle *handle, int iface)
{
	return usb_ioctl(handle, IOCTL_USBFS_RELEASEINTF, &iface);
}

static int usb_set_interface(struct libusb_device_handle *handle, int iface,
	int altsetting)
{
	struct usbfs_setinterface setintf;

	setintf.interface = iface;
	setintf.altsetting = altsetting;
	return usb_ioctl(handle, IOCTL_USBFS_SETINTF, &setintf);
}

static int usb_clear_halt(struct libusb_device_handle *handle,
	unsigned char endpoint)
{
	return usb_ioctl(handle, IOCTL_USBFS_CLEAR_HALT, &endpoint);
}

static int usb_reset_device(struct libusb_device_handle *handle)
{
	int i, r, ret = 0;

	for (i = 0; i < USB_MAXINTERFACES; i++) {
		if (handle->claimed_interfaces & (1L << i)) {
			usb_release_interface(handle, i);
		}
	}

	usb_mutex_lock(&handle->lock);
	ret = usb_ioctl(handle, IOCTL_USBFS_RESET, NULL);
	if (ret) 
		goto out;

	/* And re-claim any interfaces which were claimed before the reset */
	for (i = 0; i < USB_MAXINTERFACES; i++) {
		if (handle->claimed_interfaces & (1L << i)) {
			ret = usb_claim_interface(handle, i);
			if (ret) {
				usb_warn(HANDLE_CTX(handle),
					"failed to re-claim interface %d after reset", i);
				handle->claimed_interfaces &= ~(1L << i);
			}
		}
	}
out:
	usb_mutex_unlock(&handle->lock);
	return ret;
}

static int usb_kernel_driver_active(struct libusb_device_handle *handle,
	int interface)
{
	struct usbfs_getdriver getdrv;
	int r = 0;

	getdrv.interface = interface;
	r =  usb_ioctl(handle, IOCTL_USBFS_GETDRIVER, &getdrv);
	if (r) {
		if (errno == ENODATA)
			return 0;
		else if (errno == ENODEV)
			return LIBUSB_ERROR_NO_DEVICE;

		usb_err(HANDLE_CTX(handle),
			"get driver failed error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}

	return 1;
}

static int do_usb_kernel_driver(libusb_device_handle *handle, int interface, 
		int ioctl_code)
{
	struct usbfs_ioctl command;

	command.ifno = interface;
	command.ioctl_code = ioctl_code;
	command.data = NULL;
	return usb_ioctl(handle, IOCTL_USBFS_IOCTL, &command);
}

static int usb_detach_kernel_driver(libusb_device_handle *handle,
	int interface)
{

	return do_usb_kernel_driver(handle, interface, IOCTL_USBFS_DISCONNECT);
}

static int usb_attach_kernel_driver(libusb_device_handle *handle,
	int interface)
{
	return do_usb_kernel_driver(handle, interface, IOCTL_USBFS_CONNECT);
}

static void usb_destroy_device(struct libusb_device *dev)
{
	struct linux_device_priv *priv = _device_priv(dev);
	if (!sysfs_has_descriptors) {
		if (priv->dev_descriptor)
			free(priv->dev_descriptor);
		if (priv->config_descriptor)
			free(priv->config_descriptor);
	}
	if (priv->sysfs_dir)
		free(priv->sysfs_dir);
}

static int discard_urbs(struct usb_transfer *itransfer, int first, int last_plus_one)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_transfer_priv *tpriv =
		usb_transfer_get_os_priv(itransfer);
	int i, ret = 0;
	struct usbfs_urb *urb;

	for (i = last_plus_one - 1; i >= first; i--) {
		if (transfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
			urb = tpriv->iso_urbs[i];
		else
			urb = &tpriv->urbs[i];

		if (0 == usb_ioctl(transfer->dev_handle, IOCTL_USBFS_DISCARDURB, urb))
			continue;

		if (EINVAL == errno) {
			usb_dbg("URB not found --> assuming ready to be reaped");
			if (i == (last_plus_one - 1))
				ret = LIBUSB_ERROR_NOT_FOUND;
		} else if (ENODEV == errno) {
			usb_dbg("Device not found for URB --> assuming ready to be reaped");
			ret = LIBUSB_ERROR_NO_DEVICE;
		} else {
			usb_warn(TRANSFER_CTX(transfer),
				"unrecognised discard errno %d", errno);
			ret = LIBUSB_ERROR_OTHER;
		}
	}
	return ret;
}

static void free_iso_urbs(struct linux_transfer_priv *tpriv)
{
	int i;
	for (i = 0; i < tpriv->num_urbs; i++) {
		struct usbfs_urb *urb = tpriv->iso_urbs[i];
		if (!urb)
			break;
		free(urb);
	}

	free(tpriv->iso_urbs);
	tpriv->iso_urbs = NULL;
}

static int submit_bulk_transfer(struct usb_transfer *itransfer,
	unsigned char urb_type)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_transfer_priv *tpriv = usb_transfer_get_os_priv(itransfer);
	struct linux_device_handle_priv *dpriv =
		_device_handle_priv(transfer->dev_handle);
	struct usbfs_urb *urbs;
	int is_out = (transfer->endpoint & LIBUSB_ENDPOINT_DIR_MASK)
		== LIBUSB_ENDPOINT_OUT;
	int r;
	int i;
	size_t alloc_size;

	if (tpriv->urbs) {
		printf("urb busy!\n");
		return LIBUSB_ERROR_BUSY;
	}

	if (is_out && transfer->flags & LIBUSB_TRANSFER_ADD_ZERO_PACKET &&
	    !supports_flag_zero_packet)
		return LIBUSB_ERROR_NOT_SUPPORTED;

	int num_urbs = transfer->length / MAX_BULK_BUFFER_LENGTH;
	int last_urb_partial = 0;

	if (transfer->length == 0) {
		num_urbs = 1;
	} else if ((transfer->length % MAX_BULK_BUFFER_LENGTH) > 0) {
		last_urb_partial = 1;
		num_urbs++;
	}
	usb_dbg("need %d urbs for new transfer with length %d", num_urbs,
		transfer->length);
	alloc_size = num_urbs * sizeof(struct usbfs_urb);
	urbs = malloc(alloc_size);
	if (!urbs)
		return LIBUSB_ERROR_NO_MEM;
	memset(urbs, 0, alloc_size);
	tpriv->urbs = urbs;
	tpriv->num_urbs = num_urbs;
	tpriv->num_retired = 0;
	tpriv->reap_action = NORMAL;
	tpriv->reap_status = LIBUSB_TRANSFER_COMPLETED;

	for (i = 0; i < num_urbs; i++) {
		struct usbfs_urb *urb = &urbs[i];
		urb->usercontext = itransfer;
		urb->type = urb_type;
		urb->endpoint = transfer->endpoint;
		urb->buffer = transfer->buffer + (i * MAX_BULK_BUFFER_LENGTH);
		if (supports_flag_bulk_continuation && !is_out)
			urb->flags = USBFS_URB_SHORT_NOT_OK;
		if (i == num_urbs - 1 && last_urb_partial)
			urb->buffer_length = transfer->length % MAX_BULK_BUFFER_LENGTH;
		else if (transfer->length == 0)
			urb->buffer_length = 0;
		else
			urb->buffer_length = MAX_BULK_BUFFER_LENGTH;

		if (i > 0 && supports_flag_bulk_continuation)
			urb->flags |= USBFS_URB_BULK_CONTINUATION;

		/* we have already checked that the flag is supported */
		if (is_out && i == num_urbs - 1 &&
		    transfer->flags & LIBUSB_TRANSFER_ADD_ZERO_PACKET)
			urb->flags |= USBFS_URB_ZERO_PACKET;

		r = ioctl(dpriv->fd, IOCTL_USBFS_SUBMITURB, urb);
		if (r < 0) {
			if (errno == ENODEV) {
				r = LIBUSB_ERROR_NO_DEVICE;
			} else {
				usb_err(TRANSFER_CTX(transfer),
					"submiturb failed error %d errno=%d", r, errno);
				r = LIBUSB_ERROR_IO;
			}
	
			/* if the first URB submission fails, we can simply free up and
			 * return failure immediately. */
			if (i == 0) {
				usb_dbg("first URB failed, easy peasy");
				free(urbs);
				tpriv->urbs = NULL;
				return r;
			}

			tpriv->reap_action = EREMOTEIO == errno ? COMPLETED_EARLY : SUBMIT_FAILED;

			tpriv->num_retired += num_urbs - i;
			if (COMPLETED_EARLY == tpriv->reap_action)
				return 0;

			discard_urbs(itransfer, 0, i);

			usb_dbg("reporting successful submission but waiting for %d "
				"discards before reporting error", i);
			return 0;
		}
	}

	return 0;
}

static int submit_iso_transfer(struct usb_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_transfer_priv *tpriv = usb_transfer_get_os_priv(itransfer);
	struct linux_device_handle_priv *dpriv =
		_device_handle_priv(transfer->dev_handle);
	struct usbfs_urb **urbs;
	size_t alloc_size;
	int num_packets = transfer->num_iso_packets;
	int i;
	int this_urb_len = 0;
	int num_urbs = 1;
	int packet_offset = 0;
	unsigned int packet_len;
	unsigned char *urb_buffer = transfer->buffer;

	if (tpriv->iso_urbs)
		return LIBUSB_ERROR_BUSY;

	for (i = 0; i < num_packets; i++) {
		int space_remaining = MAX_ISO_BUFFER_LENGTH - this_urb_len;
		packet_len = transfer->iso_packet_desc[i].length;

		if (packet_len > space_remaining) {
			num_urbs++;
			this_urb_len = packet_len;
		} else {
			this_urb_len += packet_len;
		}
	}
	usb_dbg("need %d 32k URBs for transfer", num_urbs);

	alloc_size = num_urbs * sizeof(*urbs);
	urbs = malloc(alloc_size);
	if (!urbs)
		return LIBUSB_ERROR_NO_MEM;
	memset(urbs, 0, alloc_size);

	tpriv->iso_urbs = urbs;
	tpriv->num_urbs = num_urbs;
	tpriv->num_retired = 0;
	tpriv->reap_action = NORMAL;
	tpriv->iso_packet_offset = 0;

	/* allocate + initialize each URB with the correct number of packets */
	for (i = 0; i < num_urbs; i++) {
		struct usbfs_urb *urb;
		int space_remaining_in_urb = MAX_ISO_BUFFER_LENGTH;
		int urb_packet_offset = 0;
		unsigned char *urb_buffer_orig = urb_buffer;
		int j;
		int k;

		/* swallow up all the packets we can fit into this URB */
		while (packet_offset < transfer->num_iso_packets) {
			packet_len = transfer->iso_packet_desc[packet_offset].length;
			if (packet_len <= space_remaining_in_urb) {
				/* throw it in */
				urb_packet_offset++;
				packet_offset++;
				space_remaining_in_urb -= packet_len;
				urb_buffer += packet_len;
			} else {
				/* it can't fit, save it for the next URB */
				break;
			}
		}

		alloc_size = sizeof(*urb)
			+ (urb_packet_offset * sizeof(struct usbfs_iso_packet_desc));
		urb = malloc(alloc_size);
		if (!urb) {
			free_iso_urbs(tpriv);
			return LIBUSB_ERROR_NO_MEM;
		}
		memset(urb, 0, alloc_size);
		urbs[i] = urb;

		/* populate packet lengths */
		for (j = 0, k = packet_offset - urb_packet_offset;
				k < packet_offset; k++, j++) {
			packet_len = transfer->iso_packet_desc[k].length;
			urb->iso_frame_desc[j].length = packet_len;
		}

		urb->usercontext = itransfer;
		urb->type = USBFS_URB_TYPE_ISO;
		/* FIXME: interface for non-ASAP data? */
		urb->flags = USBFS_URB_ISO_ASAP;
		urb->endpoint = transfer->endpoint;
		urb->number_of_packets = urb_packet_offset;
		urb->buffer = urb_buffer_orig;
	}

	/* submit URBs */
	for (i = 0; i < num_urbs; i++) {
		int r = ioctl(dpriv->fd, IOCTL_USBFS_SUBMITURB, urbs[i]);
		if (r < 0) {
			if (errno == ENODEV) {
				r = LIBUSB_ERROR_NO_DEVICE;
			} else {
				usb_err(TRANSFER_CTX(transfer),
					"submiturb failed error %d errno=%d", r, errno);
				r = LIBUSB_ERROR_IO;
			}

			/* if the first URB submission fails, we can simply free up and
			 * return failure immediately. */
			if (i == 0) {
				usb_dbg("first URB failed, easy peasy");
				free_iso_urbs(tpriv);
				return r;
			}

			tpriv->reap_action = SUBMIT_FAILED;

			tpriv->num_retired = num_urbs - i;
			discard_urbs(itransfer, 0, i);

			usb_dbg("reporting successful submission but waiting for %d "
				"discards before reporting error", i);
			return 0;
		}
	}

	return 0;
}

static int submit_control_transfer(struct usb_transfer *itransfer)
{
	struct linux_transfer_priv *tpriv = usb_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_device_handle_priv *dpriv =
		_device_handle_priv(transfer->dev_handle);
	struct usbfs_urb *urb;
	int r;

	if (tpriv->urbs)
		return LIBUSB_ERROR_BUSY;

	if (transfer->length - LIBUSB_CONTROL_SETUP_SIZE > MAX_CTRL_BUFFER_LENGTH)
		return LIBUSB_ERROR_INVALID_PARAM;

	urb = malloc(sizeof(struct usbfs_urb));
	if (!urb)
		return LIBUSB_ERROR_NO_MEM;
	memset(urb, 0, sizeof(struct usbfs_urb));
	tpriv->urbs = urb;
	tpriv->num_urbs = 1;
	tpriv->reap_action = NORMAL;

	urb->usercontext = itransfer;
	urb->type = USBFS_URB_TYPE_CONTROL;
	urb->endpoint = transfer->endpoint;
	urb->buffer = transfer->buffer;
	urb->buffer_length = transfer->length;

	r = ioctl(dpriv->fd, IOCTL_USBFS_SUBMITURB, urb);
	if (r < 0) {
		free(urb);
		tpriv->urbs = NULL;
		if (errno == ENODEV)
			return LIBUSB_ERROR_NO_DEVICE;

		usb_err(TRANSFER_CTX(transfer),
			"submiturb failed error %d errno=%d", r, errno);
		return LIBUSB_ERROR_IO;
	}
	return 0;
}

static int usb_submit_transfer(struct usb_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return submit_control_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK:
		return submit_bulk_transfer(itransfer, USBFS_URB_TYPE_BULK);
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		return submit_bulk_transfer(itransfer, USBFS_URB_TYPE_INTERRUPT);
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return submit_iso_transfer(itransfer);
	default:
		usb_err(TRANSFER_CTX(transfer),
			"unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static int usb_cancel_transfer(struct usb_transfer *itransfer)
{
	struct linux_transfer_priv *tpriv = usb_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_BULK:
		if (tpriv->reap_action == ERROR)
			break;
		/* else, fall through */
	case LIBUSB_TRANSFER_TYPE_CONTROL:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		tpriv->reap_action = CANCELLED;
		break;
	default:
		usb_err(TRANSFER_CTX(transfer),
			"unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	if (!tpriv->urbs)
		return LIBUSB_ERROR_NOT_FOUND;

	return discard_urbs(itransfer, 0, tpriv->num_urbs);
}

static void usb_clear_transfer_priv(struct usb_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_transfer_priv *tpriv = usb_transfer_get_os_priv(itransfer);

	/* urbs can be freed also in submit_transfer so lock mutex first */
	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		usb_mutex_lock(&itransfer->lock);
		if (tpriv->urbs)
			free(tpriv->urbs);
		tpriv->urbs = NULL;
		usb_mutex_unlock(&itransfer->lock);
		break;
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		usb_mutex_lock(&itransfer->lock);
		if (tpriv->iso_urbs)
			free_iso_urbs(tpriv);
		usb_mutex_unlock(&itransfer->lock);
		break;
	default:
		usb_err(TRANSFER_CTX(transfer),
			"unknown endpoint type %d", transfer->type);
	}
}

static int handle_bulk_completion(struct usb_transfer *itransfer,
	struct usbfs_urb *urb)
{
	struct linux_transfer_priv *tpriv = usb_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	int urb_idx = urb - tpriv->urbs;

	usb_mutex_lock(&itransfer->lock);
	usb_dbg("handling completion status %d of bulk urb %d/%d", urb->status,
		urb_idx + 1, tpriv->num_urbs);

	tpriv->num_retired++;

	if (tpriv->reap_action != NORMAL) {
		/* cancelled, submit_fail, or completed early */
		usb_dbg("abnormal reap: urb status %d", urb->status);

		if (urb->actual_length > 0) {
			unsigned char *target = transfer->buffer + itransfer->transferred;
			usb_dbg("received %d bytes of surplus data", urb->actual_length);
			if (urb->buffer != target) {
				usb_dbg("moving surplus data from offset %d to offset %d",
					(unsigned char *) urb->buffer - transfer->buffer,
					target - transfer->buffer);
				memmove(target, urb->buffer, urb->actual_length);
			}
			itransfer->transferred += urb->actual_length;
		}

		if (tpriv->num_retired == tpriv->num_urbs) {
			usb_dbg("abnormal reap: last URB handled, reporting");
			if (tpriv->reap_action != COMPLETED_EARLY &&
			    tpriv->reap_status == LIBUSB_TRANSFER_COMPLETED)
				tpriv->reap_status = LIBUSB_TRANSFER_ERROR;
			goto completed;
		}
		goto out_unlock;
	}

	itransfer->transferred += urb->actual_length;

	switch (urb->status) {
	case 0:
		break;
	case -EREMOTEIO: /* short transfer */
		break;
	case -ENOENT: /* cancelled */
	case -ECONNRESET:
		break;
	case -ENODEV:
	case -ESHUTDOWN:
		usb_dbg("device removed");
		tpriv->reap_status = LIBUSB_TRANSFER_NO_DEVICE;
		goto cancel_remaining;
	case -EPIPE:
		usb_dbg("detected endpoint stall");
		if (tpriv->reap_status == LIBUSB_TRANSFER_COMPLETED)
			tpriv->reap_status = LIBUSB_TRANSFER_STALL;
		goto cancel_remaining;
	case -EOVERFLOW:
		/* overflow can only ever occur in the last urb */
		usb_dbg("overflow, actual_length=%d", urb->actual_length);
		if (tpriv->reap_status == LIBUSB_TRANSFER_COMPLETED)
			tpriv->reap_status = LIBUSB_TRANSFER_OVERFLOW;
		goto completed;
	case -ETIME:
	case -EPROTO:
	case -EILSEQ:
	case -ECOMM:
	case -ENOSR:
		usb_dbg("low level error %d", urb->status);
		tpriv->reap_action = ERROR;
		goto cancel_remaining;
	default:
		usb_warn(ITRANSFER_CTX(itransfer),
			"unrecognised urb status %d", urb->status);
		tpriv->reap_action = ERROR;
		goto cancel_remaining;
	}

	/* if we're the last urb or we got less data than requested then we're
	 * done */
	if (urb_idx == tpriv->num_urbs - 1) {
		usb_dbg("last URB in transfer --> complete!");
		goto completed;
	} else if (urb->actual_length < urb->buffer_length) {
		usb_dbg("short transfer %d/%d --> complete!",
			urb->actual_length, urb->buffer_length);
		if (tpriv->reap_action == NORMAL)
			tpriv->reap_action = COMPLETED_EARLY;
	} else
		goto out_unlock;

cancel_remaining:
	if (ERROR == tpriv->reap_action && LIBUSB_TRANSFER_COMPLETED == tpriv->reap_status)
		tpriv->reap_status = LIBUSB_TRANSFER_ERROR;

	if (tpriv->num_retired == tpriv->num_urbs) /* nothing to cancel */
		goto completed;

	/* cancel remaining urbs and wait for their completion before
	 * reporting results */
	discard_urbs(itransfer, urb_idx + 1, tpriv->num_urbs);

out_unlock:
	usb_mutex_unlock(&itransfer->lock);
	return 0;

completed:
	free(tpriv->urbs);
	tpriv->urbs = NULL;
	usb_mutex_unlock(&itransfer->lock);
	return CANCELLED == tpriv->reap_action ?
		usb_handle_transfer_cancellation(itransfer) :
		usb_handle_transfer_completion(itransfer, tpriv->reap_status);
}

static int handle_iso_completion(struct usb_transfer *itransfer,
	struct usbfs_urb *urb)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_transfer_priv *tpriv = usb_transfer_get_os_priv(itransfer);
	int num_urbs = tpriv->num_urbs;
	int urb_idx = 0;
	int i;
	enum libusb_transfer_status status = LIBUSB_TRANSFER_COMPLETED;

	usb_mutex_lock(&itransfer->lock);
	for (i = 0; i < num_urbs; i++) {
		if (urb == tpriv->iso_urbs[i]) {
			urb_idx = i + 1;
			break;
		}
	}
	if (urb_idx == 0) {
		usb_err(TRANSFER_CTX(transfer), "could not locate urb!");
		usb_mutex_unlock(&itransfer->lock);
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usb_dbg("handling completion status %d of iso urb %d/%d", urb->status,
		urb_idx, num_urbs);

	/* copy isochronous results back in */

	for (i = 0; i < urb->number_of_packets; i++) {
		struct usbfs_iso_packet_desc *urb_desc = &urb->iso_frame_desc[i];
		struct libusb_iso_packet_descriptor *lib_desc =
			&transfer->iso_packet_desc[tpriv->iso_packet_offset++];
		lib_desc->status = LIBUSB_TRANSFER_COMPLETED;
		switch (urb_desc->status) {
		case 0:
			break;
		case -ENOENT: /* cancelled */
		case -ECONNRESET:
			break;
		case -ENODEV:
		case -ESHUTDOWN:
			usb_dbg("device removed");
			lib_desc->status = LIBUSB_TRANSFER_NO_DEVICE;
			break;
		case -EPIPE:
			usb_dbg("detected endpoint stall");
			lib_desc->status = LIBUSB_TRANSFER_STALL;
			break;
		case -EOVERFLOW:
			usb_dbg("overflow error");
			lib_desc->status = LIBUSB_TRANSFER_OVERFLOW;
			break;
		case -ETIME:
		case -EPROTO:
		case -EILSEQ:
		case -ECOMM:
		case -ENOSR:
		case -EXDEV:
			usb_dbg("low-level USB error %d", urb_desc->status);
			lib_desc->status = LIBUSB_TRANSFER_ERROR;
			break;
		default:
			usb_warn(TRANSFER_CTX(transfer),
				"unrecognised urb status %d", urb_desc->status);
			lib_desc->status = LIBUSB_TRANSFER_ERROR;
			break;
		}
		lib_desc->actual_length = urb_desc->actual_length;
	}

	tpriv->num_retired++;

	if (tpriv->reap_action != NORMAL) { /* cancelled or submit_fail */
		usb_dbg("CANCEL: urb status %d", urb->status);

		if (tpriv->num_retired == num_urbs) {
			usb_dbg("CANCEL: last URB handled, reporting");
			free_iso_urbs(tpriv);
			if (tpriv->reap_action == CANCELLED) {
				usb_mutex_unlock(&itransfer->lock);
				return usb_handle_transfer_cancellation(itransfer);
			} else {
				usb_mutex_unlock(&itransfer->lock);
				return usb_handle_transfer_completion(itransfer,
					LIBUSB_TRANSFER_ERROR);
			}
		}
		goto out;
	}

	switch (urb->status) {
	case 0:
		break;
	case -ENOENT: /* cancelled */
	case -ECONNRESET:
		break;
	case -ESHUTDOWN:
		usb_dbg("device removed");
		status = LIBUSB_TRANSFER_NO_DEVICE;
		break;
	default:
		usb_warn(TRANSFER_CTX(transfer),
			"unrecognised urb status %d", urb->status);
		status = LIBUSB_TRANSFER_ERROR;
		break;
	}

	/* if we're the last urb then we're done */
	if (urb_idx == num_urbs) {
		usb_dbg("last URB in transfer --> complete!");
		free_iso_urbs(tpriv);
		usb_mutex_unlock(&itransfer->lock);
		return usb_handle_transfer_completion(itransfer, status);
	}

out:
	usb_mutex_unlock(&itransfer->lock);
	return 0;
}

static int handle_control_completion(struct usb_transfer *transfer,
	struct usbfs_urb *urb)
{
	struct linux_transfer_priv *tpriv = usb_transfer_get_os_priv(transfer);
	int status;

	usb_mutex_lock(&transfer->lock);
	usb_dbg("handling completion status %d", urb->status);

	transfer->transferred += urb->actual_length;

	if (tpriv->reap_action == CANCELLED) {
		if (urb->status != 0 && urb->status != -ENOENT)
			usb_warn(ITRANSFER_CTX(transfer),
				"cancel: unrecognised urb status %d", urb->status);
		free(tpriv->urbs);
		tpriv->urbs = NULL;
		usb_mutex_unlock(&transfer->lock);
		return usb_handle_transfer_cancellation(transfer);
	}

	switch (urb->status) {
	case 0:
		status = LIBUSB_TRANSFER_COMPLETED;
		break;
	case -ENOENT: /* cancelled */
		status = LIBUSB_TRANSFER_CANCELLED;
		break;
	case -ENODEV:
	case -ESHUTDOWN:
		usb_dbg("device removed");
		status = LIBUSB_TRANSFER_NO_DEVICE;
		break;
	case -EPIPE:
		usb_dbg("unsupported control request");
		status = LIBUSB_TRANSFER_STALL;
		break;
	case -EOVERFLOW:
		usb_dbg("control overflow error");
		status = LIBUSB_TRANSFER_OVERFLOW;
		break;
	case -ETIME:
	case -EPROTO:
	case -EILSEQ:
	case -ECOMM:
	case -ENOSR:
		usb_dbg("low-level bus error occurred");
		status = LIBUSB_TRANSFER_ERROR;
		break;
	default:
		usb_warn(ITRANSFER_CTX(transfer),
			"unrecognised urb status %d", urb->status);
		status = LIBUSB_TRANSFER_ERROR;
		break;
	}

	free(tpriv->urbs);
	tpriv->urbs = NULL;
	usb_mutex_unlock(&transfer->lock);
	return usb_handle_transfer_completion(transfer, status);
}

static int reap_for_handle(struct libusb_device_handle *handle)
{
	struct linux_device_handle_priv *hpriv = _device_handle_priv(handle);
	int r;
	struct usbfs_urb *urb;
	struct usb_transfer *itransfer;
	struct libusb_transfer *transfer;

	r = ioctl(hpriv->fd, IOCTL_USBFS_REAPURBNDELAY, &urb);
	if (r == -1 && errno == EAGAIN)
		return 1;
	if (r < 0) {
		if (errno == ENODEV)
			return LIBUSB_ERROR_NO_DEVICE;

		usb_err(HANDLE_CTX(handle), "reap failed error %d errno=%d",
			r, errno);
		return LIBUSB_ERROR_IO;
	}

	itransfer = urb->usercontext;
	transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	usb_dbg("urb type=%d status=%d transferred=%d", urb->type, urb->status,
		urb->actual_length);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return handle_iso_completion(itransfer, urb);
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		return handle_bulk_completion(itransfer, urb);
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return handle_control_completion(itransfer, urb);
	default:
		usb_err(HANDLE_CTX(handle), "unrecognised endpoint type %x",
			transfer->type);
		return LIBUSB_ERROR_OTHER;
	}
}

static int usb_handle_events(struct libusb_context *ctx,
	struct pollfd *fds, int cnt, int num_ready)
{
	int r;
	int i = 0;
	int nfds = cnt;

	usb_mutex_lock(&ctx->open_devs_lock);
	for (i = 0; i < nfds && num_ready > 0; i++) {
		struct pollfd *pollfd = &fds[i];
		struct libusb_device_handle *handle;
		struct linux_device_handle_priv *hpriv = NULL;

		if (!pollfd->revents)
			continue;

		num_ready--;
		list_for_each_entry(handle, &ctx->open_devs, list, struct libusb_device_handle) {
			hpriv = _device_handle_priv(handle);
			if (hpriv->fd == pollfd->fd)
				break;
		}

		if (pollfd->revents & POLLERR) {
			usb_remove_pollfd(HANDLE_CTX(handle), hpriv->fd);
			usb_handle_disconnect(handle);
			continue;
		}

		r = reap_for_handle(handle);
		if (r == 1 || r == LIBUSB_ERROR_NO_DEVICE)
			continue;
		else if (r < 0)
			goto out;
	}

	r = 0;
out:
	usb_mutex_unlock(&ctx->open_devs_lock);
	return r;
}

static int usb_clock_gettime(int clk_id, struct timespec *tp)
{
	switch (clk_id) {
	case USBI_CLOCK_MONOTONIC:
		return clock_gettime(CLOCK_MONOTONIC, tp);
	case USBI_CLOCK_REALTIME:
		return clock_gettime(CLOCK_REALTIME, tp);
	default:
		return LIBUSB_ERROR_INVALID_PARAM;
  }
}


const struct usb_os_backend linux_usbfs_backend = {
	.name = "Linux usbfs",
	.init = usb_init,
	.exit = NULL,
	.get_device_list = usb_get_device_list,
	.get_device_descriptor = usb_get_device_descriptor,
	.get_active_config_descriptor = usb_get_active_config_descriptor,
	.get_config_descriptor = usb_get_config_descriptor,

	.open = usbdev_open,
	.close = usbdev_close,
	.get_configuration = usb_get_configuration,
	.set_configuration = usb_set_configuration,
	.claim_interface = usb_claim_interface,
	.release_interface = usb_release_interface,

	.set_interface_altsetting = usb_set_interface,
	.clear_halt = usb_clear_halt,
	.reset_device = usb_reset_device,

	.kernel_driver_active = usb_kernel_driver_active,
	.detach_kernel_driver = usb_detach_kernel_driver,
	.attach_kernel_driver = usb_attach_kernel_driver,

	.destroy_device = usb_destroy_device,

	.submit_transfer = usb_submit_transfer,
	.cancel_transfer = usb_cancel_transfer,
	.clear_transfer_priv = usb_clear_transfer_priv,

	.handle_events = usb_handle_events,

	.clock_gettime = usb_clock_gettime,

#ifdef USBI_TIMERFD_AVAILABLE
	.get_timerfd_clockid = usb_get_timerfd_clockid,
#endif

	.device_priv_size = sizeof(struct linux_device_priv),
	.device_handle_priv_size = sizeof(struct linux_device_handle_priv),
	.transfer_priv_size = sizeof(struct linux_transfer_priv),
	.add_iso_packet_size = 0,
};

