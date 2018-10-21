# Copyright 2018 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestServiceScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestServiceScenario, cls).skip_checks()
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")
        if not CONF.kuryr_kubernetes.service_tests_enabled:
            raise cls.skipException("Service tests are not enabled")

    @classmethod
    def resource_setup(cls):
        super(TestServiceScenario, cls).resource_setup()
        cls.create_setup_for_service_test()

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdcfc1a1a9')
    def test_service_curl(self):
        LOG.info("Trying to curl the service IP %s" % self.service_ip)
        self.assert_backend_amount(self.service_ip, self.pod_num)

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdcfa1a7a9')
    def test_pod_service_curl(self):
        pod_name, pod = self.create_pod()
        self.addCleanup(self.delete_pod, pod_name)
        self.assert_backend_amount_from_pod(
            'http://{}'.format(self.service_ip),
            self.pod_num,
            pod_name)


class TestLoadBalancerServiceScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestLoadBalancerServiceScenario, cls).skip_checks()
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")
        if not CONF.kuryr_kubernetes.service_tests_enabled:
            raise cls.skipException("Service tests are not enabled")

    @classmethod
    def resource_setup(cls):
        super(TestLoadBalancerServiceScenario, cls).resource_setup()
        cls.create_setup_for_service_test(spec_type="LoadBalancer")

    @decorators.idempotent_id('bddf5441-1244-449d-a175-b5fdcfc2a1a9')
    def test_lb_service_http(self):

        LOG.info("Trying to curl the service IP %s" % self.service_ip)
        self.assert_backend_amount(self.service_ip, self.pod_num)

    # TODO(yboaron): Use multi threads for 'test_vm_service_http' test
    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdcfa1b5a9')
    def test_vm_service_http(self):
        ssh_client, fip = self.create_vm_for_connectivity_test()
        LOG.info("Trying to curl the service IP %s from VM" % self.service_ip)
        cmd = ("curl {dst_ip}".format(dst_ip=self.service_ip))

        def curl():
            return ssh_client.exec_command(cmd)
        self._run_and_assert_fn(curl)

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdbfc1b2a7')
    def test_unsupported_service_type(self):
        # Testing that kuryr controller didn't crash for 100 seconds since
        # creation of service with unsupported type
        self.create_setup_for_service_test(spec_type="NodePort", get_ip=False)
        self.check_controller_pod_status_for_time_period()

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdbfc1b2a8')
    def test_unsupported_service_protocol(self):
        # Testing that kuryr controller didn't crash for 20*5 seconds since
        # creation of service with unsupported protocol
        self.create_setup_for_service_test(protocol="UDP", get_ip=False)
        self.check_controller_pod_status_for_time_period()
