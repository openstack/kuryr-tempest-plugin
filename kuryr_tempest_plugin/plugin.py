# Copyright 2015
# All Rights Reserved.
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


import os

from tempest.test_discover import plugins

from kuryr_tempest_plugin import config as project_config


class KuryrTempestPlugin(plugins.TempestPlugin):
    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "kuryr_tempest_plugin/tests"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        conf.register_opt(project_config.service_option,
                          group='service_available')
        conf.register_opt(project_config.ports_pool_batch,
                          group='vif_pool')
        conf.register_opt(project_config.ports_pool_min,
                          group='vif_pool')
        conf.register_opt(project_config.ports_pool_max,
                          group='vif_pool')
        conf.register_opts(project_config.kuryr_k8s_opts,
                           group='kuryr_kubernetes')

    def get_opt_lists(self):
        return [('service_available', [project_config.service_option]),
                ('kuryr_kubernetes', project_config.kuryr_k8s_opts),
                ('vif_pool', [project_config.ports_pool_batch,
                              project_config.ports_pool_min,
                              project_config.ports_pool_max])]
