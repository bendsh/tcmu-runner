/*
 * Copyright 2016, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <glib.h>
#include <gio/gio.h>
#include <getopt.h>
#include <scsi/scsi.h>
#include "scsi_defs.h"

#include "libtcmu.h"
#include "version.h"
#include "libtcmu_config.h"
#include "libtcmu_log.h"

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <errno.h>
#include <scsi/scsi.h>

#include "scsi_defs.h"
#include "libtcmu.h"
#include "tcmu-runner.h"

struct file_state {
	int fd;
};

static int file_open(struct tcmu_device *dev)
{
	struct file_state *state;
	char *config;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -ENOMEM;

	tcmu_set_dev_private(dev, state);

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!config) {
		tcmu_err("no configuration found in cfgstring\n");
		goto err;
	}
	config += 1; /* get past '/' */

	tcmu_set_dev_write_cache_enabled(dev, 1);

	state->fd = open(config, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (state->fd == -1) {
		tcmu_err("could not open %s: %m\n", config);
		goto err;
	}

	tcmu_dbg("config %s\n", tcmu_get_dev_cfgstring(dev));

	return 0;

err:
	free(state);
	return -EINVAL;
}

static void file_close(struct tcmu_device *dev)
{
	struct file_state *state = tcmu_get_dev_private(dev);

	close(state->fd);
	free(state);
}

static int file_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		     struct iovec *iov, size_t iov_cnt, size_t length,
		     off_t offset)
{
	struct file_state *state = tcmu_get_dev_private(dev);
	size_t remaining = length;
	ssize_t ret;

	while (remaining) {
		ret = preadv(state->fd, iov, iov_cnt, offset);
		if (ret < 0) {
			tcmu_err("read failed: %m\n");
			ret = tcmu_set_sense_data(cmd->sense_buf, MEDIUM_ERROR,
						  ASC_READ_ERROR, NULL);
			goto done;
		}

		if (ret == 0) {
			/* EOF, then zeros the iovecs left */
			tcmu_zero_iovec(iov, iov_cnt);
			break;
		}

		tcmu_seek_in_iovec(iov, ret);
		offset += ret;
		remaining -= ret;
	}
	ret = SAM_STAT_GOOD;
done:
	cmd->done(dev, cmd, ret);
	return 0;
}

static int file_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		      struct iovec *iov, size_t iov_cnt, size_t length,
		      off_t offset)
{
	struct file_state *state = tcmu_get_dev_private(dev);
	size_t remaining = length;
	ssize_t ret;

	while (remaining) {
		ret = pwritev(state->fd, iov, iov_cnt, offset);
		if (ret < 0) {
			tcmu_err("write failed: %m\n");
			ret = tcmu_set_sense_data(cmd->sense_buf, MEDIUM_ERROR,
						  ASC_WRITE_ERROR, NULL);
			goto done;
		}
		tcmu_seek_in_iovec(iov, ret);
		offset += ret;
		remaining -= ret;
	}
	ret = SAM_STAT_GOOD;
done:
	cmd->done(dev, cmd, ret);
	return 0;
}

static int file_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct file_state *state = tcmu_get_dev_private(dev);
	int ret;

	if (fsync(state->fd)) {
		tcmu_err("sync failed\n");
		ret = tcmu_set_sense_data(cmd->sense_buf, MEDIUM_ERROR,
					  ASC_WRITE_ERROR, NULL);
		goto done;
	}
	ret = SAM_STAT_GOOD;
done:
	cmd->done(dev, cmd, ret);
	return 0;
}

static int file_reconfig(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg)
{
	switch (cfg->type) {
	case TCMULIB_CFG_DEV_SIZE:
		/*
		 * TODO - For open/reconfig we should make sure the FS the
		 * file is on is large enough for the requested size. For
		 * now assume we can grow the file and return 0.
		 */
		return 0;
	case TCMULIB_CFG_DEV_CFGSTR:
	case TCMULIB_CFG_WRITE_CACHE:
	default:
		return -EOPNOTSUPP;
	}
}

static const char file_cfg_desc[] =
	"The path to the file to use as a backstore.";

static struct tcmur_handler file_handler = {
	.cfg_desc = file_cfg_desc,

	.reconfig = file_reconfig,

	.open = file_open,
	.close = file_close,
	.read = file_read,
	.write = file_write,
	.flush = file_flush,
	.name = "File-backed Handler (example code)",
	.subtype = "file",
	.nr_threads = 2,
};

typedef struct {
	GIOChannel *gio;
	int watcher_id;
} syn_dev_t;

static int syn_handle_cmd(struct tcmu_device *dev, uint8_t *cdb,
			  struct iovec *iovec, size_t iov_cnt,
			  uint8_t *sense)
{
	uint8_t cmd;

	cmd = cdb[0];
	tcmu_dbg("syn handle cmd %d\n", cmd);

	switch (cmd) {
	case INQUIRY:
		return tcmu_emulate_inquiry(dev, NULL, cdb, iovec, iov_cnt,
					    sense);
		break;
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
		break;
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return tcmu_emulate_read_capacity_16(1 << 20,
							     512,
							     cdb, iovec,
							     iov_cnt, sense);
		else
			return TCMU_NOT_HANDLED;
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(dev, cdb, iovec, iov_cnt, sense);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(dev, cdb, iovec, iov_cnt, sense);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		return SAM_STAT_GOOD;

	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		return SAM_STAT_GOOD;

	default:
		tcmu_dbg("unknown command %x\n", cdb[0]);
		return TCMU_NOT_HANDLED;
	}
}

static gboolean syn_dev_callback(GIOChannel *source,
				 GIOCondition condition,
				 gpointer data)
{
	int ret;
	struct tcmu_device *dev = data;
	struct tcmulib_cmd *cmd;

	tcmu_dbg("dev fd cb\n");
	tcmulib_processing_start(dev);

	while ((cmd = tcmulib_get_next_command(dev)) != NULL) {
		ret = syn_handle_cmd(dev,
				     cmd->cdb,
				     cmd->iovec,
				     cmd->iov_cnt,
				     cmd->sense_buf);
		tcmulib_command_complete(dev, cmd, ret);
	}

	tcmulib_processing_complete(dev);
	return TRUE;
}

static int syn_added(struct tcmu_device *dev)
{
	syn_dev_t *s = g_new0(syn_dev_t, 1);

	tcmu_dbg("added %s\n", tcmu_get_dev_cfgstring(dev));
	tcmu_set_dev_private(dev, s);
	s->gio = g_io_channel_unix_new(tcmu_get_dev_fd(dev));
	s->watcher_id = g_io_add_watch(s->gio, G_IO_IN,
				       syn_dev_callback, dev);
	return 0;
}

static void syn_removed(struct tcmu_device *dev)
{
	syn_dev_t *s = tcmu_get_dev_private(dev);
	tcmu_dbg("removed %s\n", tcmu_get_dev_cfgstring(dev));
	g_source_remove(s->watcher_id);
	g_io_channel_unref(s->gio);
	g_free(s);
}

struct tcmulib_handler syn_handler = {
	.name = "syn",
	.subtype = "syn",
	.cfg_desc = "valid options:\n"
		    "null: a nop storage where R/W requests are completed "
		    "immediately, like the null_blk device.",
	.added = syn_added,
	.removed = syn_removed,
};

gboolean tcmulib_callback(GIOChannel *source,
			  GIOCondition condition,
			  gpointer data)
{
	struct tcmulib_context *ctx = data;

	tcmu_dbg("master fd ready\n");
	tcmulib_master_fd_ready(ctx);

	return TRUE;
}

static void usage(void) {
	printf("\nusage:\n");
	printf("\ttcmu-synthesizer [options]\n");
	printf("\noptions:\n");
	printf("\t-h, --help: print this message and exit\n");
	printf("\t-V, --version: print version and exit\n");
	printf("\t-d, --debug: enable debug messages\n");
	printf("\n");
}

static struct option long_options[] = {
	{"debug", no_argument, 0, 'd'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'V'},
	{0, 0, 0, 0},
};

int main(int argc, char **argv)
{
	GMainLoop *loop;
	GIOChannel *libtcmu_gio;
	struct tcmulib_context *ctx;

	while (1) {
		int c;
		int option_index = 0;

		c = getopt_long(argc, argv, "dhV",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			tcmu_set_log_level(TCMU_CONF_LOG_DEBUG);
			break;
		case 'V':
			printf("tcmu-synthesizer %s\n", TCMUR_VERSION);
			exit(1);
		default:
		case 'h':
			usage();
			exit(1);
		}
	}

	if (tcmu_setup_log()) {
		fprintf(stderr, "Could not setup tcmu logger.\n");
		exit(1);
	}

	ctx = tcmulib_initialize(&syn_handler, 1);
	if (!ctx) {
		tcmu_err("tcmulib_initialize failed\n");
		tcmu_destroy_log();
		exit(1);
	}

	tcmulib_register(ctx);
	/* Set up event for libtcmu */
	libtcmu_gio = g_io_channel_unix_new(tcmulib_get_master_fd(ctx));
	g_io_add_watch(libtcmu_gio, G_IO_IN, tcmulib_callback, ctx);
	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	g_main_loop_unref(loop);
	tcmu_destroy_log();
	return 0;
}
