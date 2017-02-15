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

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import constant
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils.windows import licensing

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class WindowsLicensingPlugin(base.BasePlugin):

    def _set_product_key(self, service):
        description, license_family, is_current = licensing.get_kms_product()
        if is_current:
            LOG.info('Product "%s" is already the current one, no need to set '
                     'a product key', description)
        else:
            use_avma = service.get_use_avma_licensing()
            if use_avma is None:
                use_avma = CONF.set_avma_product_key
            LOG.debug("Use AVMA: %s", use_avma)

            product_key = None
            if use_avma:
                product_key = licensing.get_volume_activation_product_key(
                    license_family, constant.VOL_ACT_AVMA)
                if not product_key:
                    LOG.error("AVMA product key not found for this OS")

            if not product_key and CONF.set_kms_product_key:
                product_key = licensing.get_volume_activation_product_key(
                    license_family, constant.VOL_ACT_KMS)
                if not product_key:
                    LOG.error("KMS product key not found for this OS")

            if product_key:
                LOG.info("Setting product key: %s", product_key)
                licensing.set_product_key(product_key)

    def _set_kms_host(self, service):
        kms_host = CONF.kms_host or service.get_kms_host()
        if kms_host:
            LOG.info("Setting KMS host: %s", kms_host)
            licensing.set_kms_host(kms_host)

    def _activate_windows(self, service):
        if CONF.activate_windows:
            # note(alexpilotti): KMS clients activate themselves
            # so this could be skipped if a KMS host is set
            LOG.info("Activating Windows")
            activation_result = licensing.activate_windows()
            LOG.debug("Activation result:\n%s" % activation_result)

    def execute(self, service, shared_data):
        osutils = osutils_factory.get_os_utils()

        if osutils.is_nano_server():
            LOG.info("Licensing info and activation are not available on "
                     "Nano Server")
        else:
            eval_end_date = licensing.is_eval()
            if eval_end_date:
                LOG.info("Evaluation license, skipping activation. "
                         "Evaluation end date: %s", eval_end_date)
            else:
                self._set_product_key(service)
                self._set_kms_host(service)
                self._activate_windows(service)

            license_info = licensing.get_licensing_info()
            LOG.info('Microsoft Windows license info:\n%s' % license_info)

        return base.PLUGIN_EXECUTION_DONE, False
