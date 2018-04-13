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

import shlex
import subprocess

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

    @decorators.skip_because(bug="1763045")
    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdcfc1a1a9')
    def test_service_curl(self):
        pod = None
        cmd_output_list = list()
        for i in range(2):
            pod_name, pod = self.create_pod(
                labels={"app": 'pod-label'}, image='celebdor/kuryr-demo')
            self.addCleanup(self.delete_pod, pod_name, pod)
        service_name, service_obj = self.create_service(
            pod_label=pod.metadata.labels)

        service_ip = self.get_service_ip(service_name)
        self.wait_service_status(
            service_ip, CONF.kuryr_kubernetes.lb_build_timeout)
        LOG.info("Trying to curl the service load balancer IP %s" % service_ip)
        cmd = "curl {dst_ip}".format(dst_ip=service_ip)
        for i in range(2):
            try:
                cmd_output_list.append(
                    subprocess.check_output(shlex.split(cmd)))
            except subprocess.CalledProcessError:
                LOG.error("Checking output of curl the service load balancer "
                          "IP %s failed" % service_ip)
                raise
