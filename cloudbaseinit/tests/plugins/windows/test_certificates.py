from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.plugins.windows import certificates
from cloudbaseinit.tests import testutils

import mock
import unittest


class ServerCerificatesPluginTests(unittest.TestCase):
	def setUp(self):
		module_path = 'cloudbaseinit.plugins.windows.certificates'
		self._cert = certificates.ServerCerificatesPlugin()
		self.snatcher = testutils.LogSnatcher(module_path)

	def _test_use_machine_keyset(self, local_machine=None, current_user=None):
		if local_machine is not None:
			store_location = constant.CERT_LOCATION_LOCAL_MACHINE
		elif current_user is not None:
			store_location = constant.CERT_LOCATION_CURRENT_USER
		else:
			store_location = "fake store_location"

		if store_location != "fake store_location":
			result = certificates.ServerCerificatesPlugin._use_machine_keyset(store_location)
			if store_location == constant.CERT_LOCATION_CURRENT_USER:
				self.assertEqual(result, False)
			elif store_location == constant.CERT_LOCATION_LOCAL_MACHINE:
				self.assertEqual(result, True)
		else:
			ex = exception.ItemNotFoundException(
                "Unsupported certificate store location: %s" %
                store_location)
			with self.assertRaises(exception.ItemNotFoundException) as exc:
				certificates.ServerCerificatesPlugin._use_machine_keyset(store_location)
			self.assertEqual(str(ex), str(exc.exception))

	def test_use_keyset_current_user(self):
		self._test_use_machine_keyset(current_user=True)

	def test_use_keyset_local_machine(self):
		self._test_use_machine_keyset(local_machine=True)

	def test_use_keyset_except(self):
		self._test_use_machine_keyset()

	def test_get_os_requirements(self):
		result = self._cert.get_os_requirements()
		self.assertEqual(result, ('win32', (5, 2)))

	@mock.patch('cloudbaseinit.utils.windows.x509.CryptoAPICertManager')
	def _test_execute(self, mock_crypto_manager, certs_info=None):
		mock_service = mock.Mock()
		mock_service.get_server_certs.return_value = certs_info
		self._cert._use_machine_keyset = mock.Mock()
		if certs_info is None:
			expected_logging = [
				"The metadata service does not provide server "
                "certificates"
			]
			call_count = 0
		else:
			call_count = len(certs_info)
			cert_info = certs_info[0]
			cert_name = cert_info.get("name")
			store_location = cert_info.get("store_location")
			store_name = cert_info.get("store_name")
			pfx_data = cert_info.get("pfx_data")
			expected_logging = [
				"Importing PFX certificate {cert_name} in store "
				"{store_location}, {store_name}".format(
				cert_name=cert_name,
				store_location=store_location,
				store_name=store_name)
			] * call_count
		with self.snatcher:
			result = self._cert.execute(mock_service, mock.sentinel)
		self.assertEqual(expected_logging, self.snatcher.output)
		self.assertEqual(result, (certificates.base.PLUGIN_EXECUTION_DONE, False))
		self.assertEquals(mock_crypto_manager.return_value.
						  import_pfx_certificate.call_count, call_count)
		self.assertEqual(self._cert._use_machine_keyset.call_count, call_count)

	def test_execute_no_certs(self):
		self._test_execute()

	def test_execute(self):
		cert_info = {
			"name": "fake_name",
			"store_location": "fake store_location",
			"store_name": "fake store_name",
			"pfx_data": "fale pfx_data"
		}
		certs_info = [cert_info] * 5
		self._test_execute(certs_info=certs_info)

