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

import kubernetes
import shlex
import subprocess
import time

from oslo_log import log as logging
from tempest import config
from tempest.lib import exceptions as lib_exc

from kuryr_tempest_plugin.tests.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestNamespaceScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestNamespaceScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.namespace_enabled:
            raise cls.skipException('Namespace driver and handler must be '
                                    'enabled to run this tests')

    @classmethod
    def setup_clients(cls):
        super(TestNamespaceScenario, cls).setup_clients()

    def test_namespace(self):
        # Check resources are created
        namespace_name, namespace = self.create_namespace()

        existing_namespaces = [ns.metadata.name
                               for ns in self.list_namespaces().items]

        self.assertIn(namespace_name, existing_namespaces)

        subnet_name = 'ns/' + namespace_name + '-subnet'
        kuryr_net_crd_name = 'ns-' + namespace_name

        seen_subnets = self.os_admin.subnets_client.list_subnets()
        seen_subnet_names = [n['name'] for n in seen_subnets['subnets']]

        self.assertIn(subnet_name, seen_subnet_names)

        subnet_id = [n['id'] for n in seen_subnets['subnets']
                     if n['name'] == subnet_name]
        net_id = [n['network_id'] for n in seen_subnets['subnets']
                  if n['name'] == subnet_name]

        kuryr_net_crd = self.get_kuryr_net_crds(kuryr_net_crd_name)

        self.assertIn(kuryr_net_crd_name, kuryr_net_crd['metadata']['name'])
        self.assertIn(kuryr_net_crd['spec']['subnetId'], subnet_id)
        self.assertIn(kuryr_net_crd['spec']['netId'], net_id)

        # Check namespace pod connectivity
        pod_name, pod = self.create_pod(labels={"app": 'pod-label'},
                                        namespace=namespace_name)
        svc_name, _ = self.create_service(pod_label=pod.metadata.labels,
                                          namespace=namespace_name)
        svc_service_ip = self.get_service_ip(service_name=svc_name,
                                             namespace=namespace_name)
        self.wait_service_status(svc_service_ip,
                                 CONF.kuryr_kubernetes.lb_build_timeout)

        cmd = "curl {dst_ip}".format(dst_ip=svc_service_ip)
        try:
            subprocess.check_output(shlex.split(cmd))
        except subprocess.CalledProcessError:
            LOG.error("Checking output of curl to the service IP %s "
                      "failed" % svc_service_ip)
            raise lib_exc.UnexpectedResponseCode()

        # Check resources are deleted
        self.delete_namespace(namespace_name)

        while True:
            time.sleep(1)
            try:
                self.get_kuryr_net_crds(kuryr_net_crd_name)
            except kubernetes.client.rest.ApiException:
                break

        existing_namespaces = [ns.metadata.name
                               for ns in self.list_namespaces().items]

        seen_subnets = self.os_admin.subnets_client.list_subnets()
        seen_subnet_names = [n['name'] for n in seen_subnets['subnets']]

        self.assertNotIn(subnet_name, seen_subnet_names)
