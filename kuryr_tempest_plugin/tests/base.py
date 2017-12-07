# Copyright 2017 Red Hat, Inc.
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

from tempest.api.network import base
from tempest import config

CONF = config.CONF


class BaseAdminKuryrTest(base.BaseAdminNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(BaseAdminKuryrTest, cls).skip_checks()
        if not CONF.service_available.kuryr:
            raise cls.skipException('Kuryr support is required')

    @classmethod
    def resource_setup(cls):
        super(BaseAdminKuryrTest, cls).resource_setup()
        # TODO(dmellado): Config k8s client in a cleaner way
        kubernetes.config.load_kube_config()
        cls.k8s_client = kubernetes.client.CoreV1Api()
