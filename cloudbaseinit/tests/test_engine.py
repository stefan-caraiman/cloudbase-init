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

import importlib
import sys
import unittest

import mock

from cloudbaseinit.tests import testutils


class EngineTestMixin(object):

    def setUp(self):
        self._multiprocessing_mock = mock.Mock()
        self._manager_mock = mock.Mock()
        self._threading_mock = mock.Mock()
        self._mock_service_factory = mock.MagicMock()
        self._mock_log = mock.Mock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'multiprocessing': self._multiprocessing_mock,
             'threading': self._threading_mock})

        self._module_patcher.start()
        self._engine_module = importlib.import_module('cloudbaseinit.engine')
        self._engine_module.multiprocessing = self._multiprocessing_mock
        self._engine_module.threading = self._threading_mock
        self._engine_module.service_factory = self._mock_service_factory
        self._engine_module.log = self._mock_log
        super(EngineTestMixin, self).setUp()

    def tearDown(self):
        self._module_patcher.stop()
        super(EngineTestMixin, self).tearDown()
        sys.modules.pop('cloudbaseinit.engine', None)


class EngineTest(EngineTestMixin, unittest.TestCase):

    def setUp(self):
        super(EngineTest, self).setUp()
        self._engine = self._engine_module.ExecutionEngine(
            self._manager_mock())

    def test_service_loaded_callback_no_service(self):
        shared_data = mock.Mock()

        self._engine_module._service_loaded_callback(None, shared_data)

        self.assertFalse(shared_data.append.called)

    def test_service_loaded_callback(self):
        service = mock.Mock()
        shared_data = mock.Mock()

        with testutils.LogSnatcher('cloudbaseinit.engine') as snatcher:
            self._engine_module._service_loaded_callback(service, shared_data)

        service.get_instance_id.assert_called_once_with()
        shared_data.append.assert_called_once_with(service)
        expected_logging = [
            'Metadata service loaded: \'%s\'' % service.get_name.return_value,
            'Instance id: %s' % service.get_instance_id.return_value
        ]
        self.assertEqual(expected_logging, snatcher.output)

    def test_load_metadata_service_failed_to_load(self):
        service = mock.Mock()
        service.load.side_effect = Exception

        with testutils.LogSnatcher('cloudbaseinit.engine') as snatcher:
            self._engine_module._load_metadata_service(service)

        service.load.assert_called_once_with()
        expected_logging = (
            "Trying to load service %s" % service.get_name.return_value
        )
        exception_msg = "Failed to load metadata service '%r'" % service
        self.assertEqual(expected_logging, snatcher.output[0])
        self.assertTrue(snatcher.output[1].startswith(exception_msg))

    def test_load_metadata_service(self):
        service = mock.Mock()
        with testutils.LogSnatcher('cloudbaseinit.engine') as snatcher:
            self._engine_module._load_metadata_service(service)

        service.load.assert_called_once_with()
        expected_logging = [
            "Trying to load service %s" % service.get_name.return_value,
            "Service %s was loaded." % service.get_name.return_value
        ]
        self.assertEqual(expected_logging, snatcher.output)

    @mock.patch('cloudbaseinit.engine.plugins_factory')
    def test_run_stage_no_plugins_for_stage(self, mock_plugins_factory):
        mock_plugins_factory.load_plugins.return_value = None

        with testutils.LogSnatcher('cloudbaseinit.engine') as snatcher:
            self._engine.run_stage(mock.sentinel.stage)

        expected_output = [
            'Executing plugins for stage %r' % mock.sentinel.stage,
            'No plugins for stage %r' % mock.sentinel.stage,
        ]
        self.assertEqual(expected_output, snatcher.output)

    @mock.patch('cloudbaseinit.engine.ExecutionEngine._execute_plugins')
    @mock.patch('cloudbaseinit.engine.plugins_factory')
    def test_run_stage(self, mock_plugins_factory, mock_execute_plugins):
        mock_pool = mock.MagicMock()
        self._engine_module._Pool = mock_pool
        plugins = [mock.sentinel.plugin1,
                   mock.sentinel.plugin2,
                   mock.sentinel.plugin3]
        mock_plugins_factory.load_plugins.return_value = plugins
        mock_execute_plugins.side_effect = [False, True, False]

        self._engine.run_stage(mock.sentinel.stage)

        mock_plugins_factory.load_plugins.assert_called_once_with(
            mock.sentinel.stage)
        self._multiprocessing_mock.Manager.assert_called_once_with()
        manager = self._multiprocessing_mock.Manager.return_value
        plugins_shared_data = manager.dict.return_value

        created_pool = mock_pool.return_value.__enter__.return_value
        expected_calls = [
            mock.call(mock.sentinel.plugin1, created_pool,
                      plugins_shared_data),
            mock.call(mock.sentinel.plugin2, created_pool,
                      plugins_shared_data),
        ]
        self.assertEqual(mock_execute_plugins.mock_calls, expected_calls)

    def test_engine_terminate(self):
        manager = mock.Mock()
        self._engine._service_manager = manager

        self._engine.terminate()
        self._engine._pool_manager.shutdown.assert_called_once_with()

    def test_start_async_service_search(self):
        manager = mock.Mock()
        self._engine._service_manager = manager

        self._engine.start_async_service_search()

        manager.start_async_search.assert_called_once_with()

    def test__wait_futures(self):
        future1 = mock.Mock()
        future2 = mock.Mock()
        future3 = mock.Mock()
        futures = [future1, future2, future3]
        future1.get.return_value = False
        future2.get.return_value = True
        future3.get.return_value = False

        self.assertTrue(self._engine._wait_futures(futures))
        future1.get.assert_called_once_with()
        future2.get.assert_called_once_with()
        future3.get.assert_called_once_with()

    def test__call_later(self):
        pool = mock.Mock()

        result = self._engine._call_later(
            mock.sentinel.plugin,
            mock.sentinel.service,
            pool, mock.sentinel.plugins_shared_data)

        pool.apply_async.assert_called_once_with(
            self._engine_module._run_plugin,
            args=(mock.sentinel.plugin, self._engine._init_manager,
                  mock.sentinel.service, mock.sentinel.plugins_shared_data))
        self.assertEqual(result, pool.apply_async.return_value)

    @mock.patch('cloudbaseinit.engine.ExecutionEngine._wait_futures')
    @mock.patch('cloudbaseinit.engine.ExecutionEngine._call_later')
    def test__execute_plugins(self, mock_call_later, mock_wait_futures):
        manager = mock.Mock()
        manager.get_plugin_service.side_effect = [
            self._engine_module.ServiceSearchInProgress,
            self._engine_module.ServiceSearchInProgress,
            mock.sentinel.service1,
            self._engine_module.NoServiceCapableEnoughError,
            self._engine_module.NoServiceCapableEnoughError,
        ]
        self._engine._service_manager = manager
        mock_plugin1 = mock.Mock()
        mock_plugin2 = mock.Mock()
        mock_plugin3 = mock.Mock()
        plugins = [mock_plugin1, mock_plugin2, mock_plugin3]

        with testutils.LogSnatcher('cloudbaseinit.engine') as snatcher:
            self._engine._execute_plugins(
                plugins, mock.sentinel.pool,
                mock.sentinel.plugins_shared_data)

        call_later_calls = [
            mock.call(mock_plugin1, mock.sentinel.service1,
                      mock.sentinel.pool, mock.sentinel.plugins_shared_data)
        ]
        expected_output = [
            "No service capable enough for running plugin %s"
            % mock_plugin3.get_name.return_value,
            "No service capable enough for running plugin %s"
            % mock_plugin2.get_name.return_value,
        ]

        self.assertEqual(expected_output, snatcher.output)
        self.assertEqual(call_later_calls, mock_call_later.mock_calls)
        mock_wait_futures.assert_called_once_with(
            [mock_call_later.return_value])


class TestPool(EngineTestMixin, unittest.TestCase):

    def test_init(self):
        mock_queue = self._multiprocessing_mock.Queue
        mock_pool = self._multiprocessing_mock.Pool
        self._engine_module._Pool(mock.sentinel.workers)

        mock_queue.assert_called_once_with()
        self._mock_log.LogConsumer.assert_called_once_with(
            mock_queue.return_value)
        mock_pool.assert_called_once_with(
            mock.sentinel.workers,
            initializer=self._engine_module._pool_initializer,
            initargs=(mock_queue.return_value, ))
        consumer = self._mock_log.LogConsumer.return_value
        consumer.start_consume.assert_called_once_with()

    def test_terminate(self, *_):
        pool = self._engine_module._Pool(mock.sentinel.workers)
        pool.terminate()

        pool._pool.terminate.assert_called_once_with()
        pool._consumer.finish_consume.assert_called_once_with()

    def test_apply_async(self, *_):
        pool = self._engine_module._Pool(mock.sentinel.workers)
        result = pool.apply_async(mock.sentinel.arg1, mock.sentinel.arg2)

        underlying_pool = self._multiprocessing_mock.Pool.return_value
        underlying_pool.apply_async.assert_called_once_with(
            mock.sentinel.arg1,
            mock.sentinel.arg2)
        self.assertEqual(underlying_pool.apply_async.return_value, result)

    def test_context_manager(self, *_):
        with self._engine_module._Pool(mock.sentinel.workers) as pool:
            self.assertFalse(pool._pool.terminate.called)
        self.assertTrue(pool._pool.terminate.called)


class TestServiceManager(EngineTestMixin, unittest.TestCase):

    def setUp(self):
        super(TestServiceManager, self).setUp()
        self._mock_container = mock.MagicMock()
        self._manager = self._engine_module._ServiceManager(
            self._mock_container)

    def test_start_async_search(self):
        self._manager.start_async_search()

        self._threading_mock.Thread.assert_called_once_with(
            target=self._manager._start_search)
        thread = self._threading_mock.Thread.return_value
        thread.start.assert_called_once_with()

    def test_terminate(self):
        mock_service_1 = mock.Mock()
        mock_service_2 = mock.Mock()
        mock_services = [mock_service_1, mock_service_2]
        self._manager._completed_services = mock_services

        self._manager.terminate()

        mock_service_1.cleanup.assert_called_once_with()
        mock_service_2.cleanup.assert_called_once_with()

    @mock.patch('functools.partial')
    def test__start_search(self, mock_partial):
        mock_pool = mock.Mock()
        self._manager._pool = mock_pool

        self._manager._start_search()

        callback = mock_partial(self._engine_module._service_loaded_callback,
                                shared_data=self._manager._completed_services)

        mock_calls = [mock.call(self._engine_module._load_metadata_service,
                                args=(service, ), callback=callback)
                      for service in self._manager._services]
        self.assertEqual(mock_calls, mock_pool.apply_async.mock_calls)
        mock_future = mock_pool.apply_async.return_value
        wait_calls = [mock.call() for _ in range(len(mock_calls))]
        self.assertEqual(mock_future.wait.mock_calls, wait_calls)
        self.assertEqual(self._manager._finalized, len(mock_calls))
