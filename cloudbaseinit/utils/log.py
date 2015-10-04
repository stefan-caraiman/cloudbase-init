# Copyright 2014 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import serial
import threading
import traceback

from oslo_log import formatters
from oslo_log import log
import six

from cloudbaseinit import conf as cloudbaseinit_conf

CONF = cloudbaseinit_conf.CONF
LOG = log.getLogger(__name__)


class SerialPortHandler(logging.StreamHandler):

    class _UnicodeToBytesStream(object):

        def __init__(self, stream):
            self._stream = stream

        def write(self, data):
            if self._stream and not self._stream.isOpen():
                    self._stream.open()

            if isinstance(data, six.text_type):
                self._stream.write(data.encode("utf-8"))
            else:
                self._stream.write(data)

    def __init__(self):
        self._port = None
        if CONF.logging_serial_port_settings:
            settings = CONF.logging_serial_port_settings.split(',')

            try:
                self._port = serial.Serial(port=settings[0],
                                           baudrate=int(settings[1]),
                                           parity=settings[2],
                                           bytesize=int(settings[3]))
                if not self._port.isOpen():
                    self._port.open()
            except serial.SerialException as ex:
                # Log to other handlers
                LOG.exception(ex)

        # Unicode strings are not properly handled by the serial module
        super(SerialPortHandler, self).__init__(
            self._UnicodeToBytesStream(self._port))

    def close(self):
        if self._port and self._port.isOpen():
            self._port.close()


class MultiprocessHandler(logging.Handler):
    """Logging handler which emits records into a given queue."""

    def __init__(self, queue):
        self.queue = queue
        logging.Handler.__init__(self)

    def _enqueue(self, record):
        self.queue.put_nowait(record)

    def _prepare(self, record):
        record.tb = None
        if record.exc_info:
            tb = "".join(traceback.format_exception(*record.exc_info))
            record.tb = tb

        record.msg = record.getMessage()
        # Reset the arguments and the exc_info members, because
        # they can contain objects which aren't picklable, which
        # is actually the case for traceback objects.
        record.args = None
        record.exc_info = None
        return record

    def emit(self, record):
        self._enqueue(self._prepare(record))


def _consume_log_queue(process_queue, event):
    while not event.is_set():
        try:
            record = process_queue.get(timeout=0.5)
        except six.moves.queue.Empty:
            continue

        # Use the underlying logger member because we need
        # to process the log record we have.
        LOG.logger.handle(record)
        if record.tb:
            LOG.info(record.tb)


def setup(product_name):
    log.setup(CONF, product_name)

    if CONF.logging_serial_port_settings:
        log_root = log.getLogger(product_name).logger

        serialportlog = SerialPortHandler()
        log_root.addHandler(serialportlog)

        datefmt = CONF.log_date_format
        serialportlog.setFormatter(
            formatters.ContextFormatter(project=product_name,
                                        datefmt=datefmt))


def setup_worker(product_name, queue):
    log.setup(CONF, product_name)
    logging.basicConfig(level=logging.DEBUG)

    logger = log.getLogger(product_name).logger
    pipe_handler = MultiprocessHandler(queue)
    logger.addHandler(pipe_handler)
    logger.propagate = False


class LogConsumer(object):
    """Consume logs from the given queue."""

    def __init__(self, log_queue):
        self._event = threading.Event()
        self._thread = threading.Thread(target=_consume_log_queue,
                                        args=(log_queue, self._event))

    def start_consume(self):
        self._thread.start()

    def finish_consume(self):
        self._event.set()
        self._thread.join()

    def __enter__(self):
        self.start_consume()
        return self

    def __exit__(self, *_):
        self.finish_consume()
