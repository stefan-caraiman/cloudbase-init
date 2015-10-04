# Copyright 2015 Cloudbase Solutions Srl
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

import collections
import functools
import multiprocessing
import sys
import threading

from oslo_config import cfg
from oslo_log import log as oslo_logging

from cloudbaseinit.metadata import factory as service_factory
from cloudbaseinit.metadata.services import base
from cloudbaseinit.plugins import factory as plugins_factory
from cloudbaseinit.utils import log


CONF = cfg.CONF
LOG = oslo_logging.getLogger(__name__)
_REQUIRED_CAPABILITY_WEIGHT = 100


class NoServiceCapableEnoughError(Exception):
    """Raised when a service capable enough for a plugin was not found."""


class ServiceSearchInProgress(Exception):
    pass


def _pool_initializer(log_queue):
    """Called by each worker before being created.

    This prepares the worker with whatever is necessary for it
    to act, such as using the config file and enabling the logger.
    """
    CONF(sys.argv[1:])
    log.setup_worker('cloudbaseinit', log_queue)


def _run_plugin(plugin, manager, service, plugins_shared_data):
    return manager.exec_plugin(service, plugin,
                               plugins_shared_data)


def _service_loaded_callback(service, shared_data):
    if service:
        LOG.info('Metadata service loaded: \'%s\'' %
                 service.get_name())

        instance_id = service.get_instance_id()
        LOG.debug('Instance id: %s', instance_id)
        shared_data.append(service)


def _load_metadata_service(service):
    LOG.info("Trying to load service %s", service.get_name())
    try:
        if service.load():
            LOG.info("Service %s was loaded.", service.get_name())
            return service
    except Exception:
        LOG.exception("Failed to load metadata service '%r'", service)


class _Pool(object):

    def __init__(self, workers):
        log_queue = multiprocessing.Queue()
        self._consumer = log.LogConsumer(log_queue)
        self._pool = multiprocessing.Pool(workers,
                                          initializer=_pool_initializer,
                                          initargs=(log_queue, ))
        self._consumer.start_consume()

    def terminate(self):
        self._pool.terminate()
        self._consumer.finish_consume()

    def apply_async(self, *args, **kwargs):
        return self._pool.apply_async(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.terminate()


class _ServiceManager(object):

    def __init__(self, services_container):
        self._completed_services = services_container
        self._finalized = 0
        self._services = service_factory.load_services()
        self._pool = _Pool(len(self._services))
        self._search_thread = None
        self._aggregates = collections.defaultdict(list)
        for service in self._services:
            name = service.aggregated_group()
            if name:
                self._aggregates[name].append(service)

    def get_plugin_service(self, plugin):
        """Get a metadata service for the given plugin

        If the plugin doesn't define any capabilities, then no
        metadata service will be given to it, since it can run without
        one.

        The algorithm tries to find first a metadata service that has
        all the capabilities mandatory for the plugin and if no such
        metadata is found, then it will raise
        :exc:`NoServiceCapableEnoguhError`. On the other hand,
        :exc:`ServiceSearchInProgress` will be raised if no metadata
        service was found, but if the underlying search didn't finish
        yet.
        """

        if (not plugin.optional_capabilities
                and not plugin.required_capabilities):
            # Does not need a metadata service.
            return None

        if self._finalized != len(self._services):
            # The search is in progress.
            stop = ServiceSearchInProgress
        else:
            # The search is over.
            stop = NoServiceCapableEnoughError

        # Determine the proper metadata service, by giving a bigger
        # weight to services which have all the required capabilities
        # for this plugin. A smaller weight will be given to services
        # which provides as many optional capabilities as possible.
        # In the end, a service with only one required capability
        # weights a lot more than a service with all the optional
        # capabilities for this plugin.
        weighted = collections.defaultdict(int)
        required_caps = set(plugin.required_capabilities)
        if required_caps:
            for service in self._completed_services:
                service_caps = set(service.supported_capabilities)
                if required_caps.issubset(service_caps):
                    weighted[service] = _REQUIRED_CAPABILITY_WEIGHT

            if not weighted:
                # No need to look further, since no other service
                # will be found.
                raise stop

        optional_caps = set(plugin.optional_capabilities)
        if optional_caps:
            for service in self._completed_services:
                service_capabilities = set(service.supported_capabilities)
                weight = len(optional_caps.intersection(service_capabilities))
                weighted[service] += weight

        return self._pick_service(weighted, stop)

    def _pick_service(self, services, stop):
        """Pick a proper service from the given list of services

        The services are sorted by their weights, services with a better
        weight being more useful to the given plugin.
        If the first service belongs to an aggregate group, then we'll
        wait for the entire aggregate group to finish before giving
        the service to the plugin.
        """
        services = sorted(services, key=lambda key: services[key],
                          reverse=True)
        service = services[0]
        aggregate_cls = service.aggregated_group()

        if aggregate_cls:
            all_aggregates = self._aggregates[aggregate_cls]
            loaded_aggregates = [
                _service for _service in self._completed_services
                if _service.aggregated_group() == aggregate_cls
            ]

            if len(loaded_aggregates) != len(all_aggregates):
                raise stop

            return aggregate_cls(*loaded_aggregates)

        return base.AggregateService(service)

    def _start_search(self):
        callback = functools.partial(_service_loaded_callback,
                                     shared_data=self._completed_services)
        futures = [self._pool.apply_async(_load_metadata_service,
                                          args=(service, ),
                                          callback=callback)
                   for service in self._services]

        for future in futures:
            future.wait()
            self._finalized += 1

    def start_async_search(self):
        self._search_thread = threading.Thread(target=self._start_search)
        self._search_thread.start()

    def terminate(self):
        for service in self._completed_services:
            service.cleanup()
        self._pool.terminate()


class ExecutionEngine(object):
    """Class responsible for running plugins

    The execution of plugins implies a couple of concepts:

        * the plugins are split into various stages
        * each stage has its plugins partitioned into various
          priority groups, orderered by a given priority.
          This means that some plugins need to run before
          others.
        * for each plugin, a proper metadata service will be retrieved,
          as long as one can be found with the capabilities that the
          plugin requires. The discovery of the metadata services is
          also done in parallel.
    """

    def __init__(self, manager):
        self._init_manager = manager
        self._pool_manager = multiprocessing.Manager()
        self._service_manager = _ServiceManager(self._pool_manager.list())

    def _call_later(self, plugin, service, pool, plugins_shared_data):
        return pool.apply_async(_run_plugin,
                                args=(plugin, self._init_manager,
                                      service, plugins_shared_data))

    @staticmethod
    def _wait_futures(futures):
        reboot_required = False
        for future in futures:
            result = future.get()
            reboot_required = result or reboot_required
        return reboot_required

    def _execute_plugins(self, plugins, pool, plugins_shared_data):
        futures = []
        plugins = collections.deque(plugins)

        while plugins:
            plugin = plugins.pop()
            try:
                service = self._service_manager.get_plugin_service(plugin)
            except NoServiceCapableEnoughError:
                # No service capable enough for this plugin.
                LOG.warning("No service capable enough for running plugin %s",
                            plugin.get_name())
                continue
            except ServiceSearchInProgress:
                # The engine is still looking for a service
                # that's capable enough for this plugin.
                plugins.appendleft(plugin)
                continue
            futures.append(
                self._call_later(plugin, service, pool, plugins_shared_data))

        reboot_required = self._wait_futures(futures)
        return reboot_required

    def start_async_service_search(self):
        self._service_manager.start_async_search()

    def terminate(self):
        self._service_manager.terminate()
        self._pool_manager.shutdown()

    def run_stage(self, stage):
        """Run the plugins for the given stage."""
        LOG.info('Executing plugins for stage %r', stage)

        plugins = plugins_factory.load_plugins(stage)
        if not plugins:
            LOG.info('No plugins for stage %r', stage)
            return False

        plugins_shared_data = self._pool_manager.dict()
        with _Pool(len(plugins)) as pool:
            for plugins_group in plugins:
                reboot_required = self._execute_plugins(
                    plugins_group, pool, plugins_shared_data)
                if reboot_required:
                    # Short circuit the other plugin partitions,
                    # since we need to restart as soon as possible.
                    return reboot_required
