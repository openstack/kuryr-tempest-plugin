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
import time

from oslo_concurrency import lockutils
from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import consts

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestPortPoolScenario(base.BaseKuryrScenarioTest):
    CONFIG_MAP_NAME = 'kuryr-config'
    CONF_TO_UPDATE = 'kuryr.conf'
    VIF_POOL_SECTION = 'vif_pool'

    @classmethod
    def skip_checks(cls):
        super(TestPortPoolScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.namespace_enabled:
            raise cls.skipException('Namespace driver and handler must be '
                                    'enabled to run these tests')
        if not CONF.kuryr_kubernetes.port_pool_enabled:
            raise cls.skipException(
                "Port pool feature should be enabled to run these tests.")

    @classmethod
    def resource_setup(cls):
        super(TestPortPoolScenario, cls).resource_setup()
        cls.PORTS_POOL_DEFAULT_DICT = cls.get_config_map_ini_value(
            name=cls.CONFIG_MAP_NAME, conf_for_get=cls.CONF_TO_UPDATE,
            section=cls.VIF_POOL_SECTION, keys=[
                'ports_pool_batch', 'ports_pool_min', 'ports_pool_max',
                'ports_pool_update_frequency'])

    def get_subnet_id_for_ns(self, namespace_name):
        subnet_name = 'ns/' + namespace_name + '-subnet'
        subnets_list = self.os_admin.subnets_client.list_subnets()
        subnet_id = [n['id'] for n in subnets_list['subnets']
                     if n['name'] == subnet_name][0]
        return subnet_id

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fddfb1a3aa')
    @lockutils.synchronized('port-pool-restarts')
    def test_port_pool(self):
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        subnet_id = self.get_subnet_id_for_ns(namespace_name)

        # check the original length of list of ports for new ns
        port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        # create a pod to test the port pool increase
        pod_name1, _ = self.create_pod(namespace=namespace_name,
                                       labels={'type': 'demo'})

        # port number should increase by ports_pool_batch value
        updated_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        LOG.info("New_port_list_num = {} while pool_batch_conf = {}".format(
            updated_port_list_num, self.PORTS_POOL_DEFAULT_DICT[
                'ports_pool_batch']))
        num_to_compare = updated_port_list_num - int(
            self.PORTS_POOL_DEFAULT_DICT['ports_pool_batch'])
        self.assertEqual(num_to_compare, port_list_num)

        # create additional pod
        self.create_pod(namespace=namespace_name,
                        affinity={'podAffinity': consts.POD_AFFINITY})

        # the port pool should stay the same
        updated2_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        self.assertEqual(updated_port_list_num, updated2_port_list_num)

        # to test the reload of the pools, we will also test the restart of the
        # kuryr-controller
        self.restart_kuryr_controller()

        port_list_num_after_restart = len(
            self.os_admin.ports_client.list_ports(
                fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        self.assertEqual(updated_port_list_num, port_list_num_after_restart,
                         "Number of Neutron ports on namespace %s subnet "
                         "changed after kuryr-controller "
                         "restart" % namespace_name)

        # create additional pod
        pod_name3, _ = self.create_pod(
            namespace=namespace_name,
            affinity={'podAffinity': consts.POD_AFFINITY})

        # the total number of ports should stay the same
        updated3_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        self.assertEqual(updated_port_list_num, updated3_port_list_num)

        # check connectivity between pods
        pod_ip = self.get_pod_ip(pod_name1, namespace=namespace_name)
        cmd = [
            "/bin/sh", "-c", "ping -c 4 {dst_ip}>/dev/null ; echo $?".format(
                dst_ip=pod_ip)]
        self.assertEqual(self.exec_command_in_pod(
            pod_name3, cmd, namespace=namespace_name), '0')

    @decorators.idempotent_id('bddd5441-1244-429d-a125-b55ddfb134a9')
    @lockutils.synchronized('port-pool-restarts')
    def test_port_pool_update(self):
        UPDATED_POOL_BATCH = 3

        # Check resources are created
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        subnet_id = self.get_subnet_id_for_ns(namespace_name)
        self.update_config_map_ini_section_and_restart(
            name=self.CONFIG_MAP_NAME,
            conf_to_update=self.CONF_TO_UPDATE,
            section=self.VIF_POOL_SECTION,
            ports_pool_max=0,
            ports_pool_batch=UPDATED_POOL_BATCH,
            ports_pool_min=1)
        self.addCleanup(
            self.update_config_map_ini_section_and_restart,
            self.CONFIG_MAP_NAME, self.CONF_TO_UPDATE, self.VIF_POOL_SECTION,
            ports_pool_batch=self.PORTS_POOL_DEFAULT_DICT['ports_pool_batch'],
            ports_pool_max=self.PORTS_POOL_DEFAULT_DICT['ports_pool_max'],
            ports_pool_min=self.PORTS_POOL_DEFAULT_DICT['ports_pool_min'])

        # check the original length of list of ports for new ns
        port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        # create a pod to test the port pool increase by updated value
        pod_name1, pod1 = self.create_pod(namespace=namespace_name,
                                          labels={'type': 'demo'})

        # port number should increase by updated ports_pool_batch value
        updated_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        num_to_compare = updated_port_list_num - UPDATED_POOL_BATCH
        self.assertEqual(num_to_compare, port_list_num)

        # create additional pod
        pod_name2, pod2 = self.create_pod(
            namespace=namespace_name,
            affinity={'podAffinity': consts.POD_AFFINITY})

        # the total number of ports should stay the same
        updated2_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        self.assertEqual(updated_port_list_num, updated2_port_list_num)

        # check connectivity between pods
        pod_ip = self.get_pod_ip(pod_name1, namespace=namespace_name)
        cmd = [
            "/bin/sh", "-c", "ping -c 4 {dst_ip}>/dev/null ; echo $?".format(
                dst_ip=pod_ip)]
        self.assertEqual(self.exec_command_in_pod(
            pod_name2, cmd, namespace=namespace_name), '0')

    @decorators.idempotent_id('bddd5441-1244-459d-a133-b56ddfb147a6')
    @lockutils.synchronized('port-pool-restarts')
    def test_port_pool_noop_update(self):
        KUBERNETES_SECTION = 'kubernetes'
        VIF_POOL_SECTION = 'vif_pool'

        # Check resources are created
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        subnet_id = self.get_subnet_id_for_ns(namespace_name)

        # Read the value of the drivers
        update_pools_vif_drivers = self.get_config_map_ini_value(
            name=self.CONFIG_MAP_NAME, conf_for_get=self.CONF_TO_UPDATE,
            section=VIF_POOL_SECTION,
            keys=['pools_vif_drivers'])['pools_vif_drivers']
        vif_pool_driver = self.get_config_map_ini_value(
            name=self.CONFIG_MAP_NAME, conf_for_get=self.CONF_TO_UPDATE,
            section=KUBERNETES_SECTION,
            keys=['vif_pool_driver'])['vif_pool_driver']

        if update_pools_vif_drivers:
            self.update_config_map_ini_section(
                name=self.CONFIG_MAP_NAME,
                conf_to_update=self.CONF_TO_UPDATE,
                section=VIF_POOL_SECTION,
                pools_vif_drivers='')
            self.addCleanup(
                self.update_config_map_ini_section,
                self.CONFIG_MAP_NAME, self.CONF_TO_UPDATE, VIF_POOL_SECTION,
                pools_vif_drivers=update_pools_vif_drivers)

        self.update_config_map_ini_section_and_restart(
            name=self.CONFIG_MAP_NAME,
            conf_to_update=self.CONF_TO_UPDATE,
            section=KUBERNETES_SECTION,
            vif_pool_driver='noop')
        self.addCleanup(
            self.update_config_map_ini_section_and_restart,
            self.CONFIG_MAP_NAME, self.CONF_TO_UPDATE, KUBERNETES_SECTION,
            vif_pool_driver=vif_pool_driver)

        # check the original length of list of ports for new ns
        port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        # create a pod to test the port pool increase by 1
        self.create_pod(namespace=namespace_name, labels={'type': 'demo'})

        # port number should increase by 1
        new_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])

        self.assertEqual(port_list_num+1, new_port_list_num)

        # update pools_vif_drivers and vif_pool_driver to the previous values
        if update_pools_vif_drivers:
            self.update_config_map_ini_section(
                name=self.CONFIG_MAP_NAME,
                conf_to_update=self.CONF_TO_UPDATE,
                section=VIF_POOL_SECTION,
                pools_vif_drivers='')

        self.update_config_map_ini_section_and_restart(
            name=self.CONFIG_MAP_NAME,
            conf_to_update=self.CONF_TO_UPDATE,
            section=KUBERNETES_SECTION,
            vif_pool_driver=vif_pool_driver)

        # check that everything works as before when returning back from noop
        # configuration for vif_pool_driver
        self.create_pod(namespace=namespace_name,
                        affinity={'podAffinity': consts.POD_AFFINITY})

        # port number should increase by default ports_pool_batch value
        updated_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        num_to_compare = updated_port_list_num - int(
            self.PORTS_POOL_DEFAULT_DICT['ports_pool_batch'])
        self.assertEqual(num_to_compare, new_port_list_num)

    @decorators.idempotent_id('bddd5441-1244-429d-a123-b55ddfb137a6')
    @lockutils.synchronized('port-pool-restarts')
    def test_port_pool_min_max_update(self):
        POOL_BATCH = 2
        POOL_MAX = 2
        POOL_MIN = 1

        # Check resources are created
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        subnet_id = self.get_subnet_id_for_ns(namespace_name)

        self.update_config_map_ini_section_and_restart(
            name=self.CONFIG_MAP_NAME,
            conf_to_update=self.CONF_TO_UPDATE,
            section=self.VIF_POOL_SECTION,
            ports_pool_max=POOL_MAX,
            ports_pool_batch=POOL_BATCH,
            ports_pool_min=POOL_MIN)
        self.addCleanup(
            self.update_config_map_ini_section_and_restart,
            self.CONFIG_MAP_NAME, self.CONF_TO_UPDATE, self.VIF_POOL_SECTION,
            ports_pool_batch=self.PORTS_POOL_DEFAULT_DICT['ports_pool_batch'],
            ports_pool_max=self.PORTS_POOL_DEFAULT_DICT['ports_pool_max'],
            ports_pool_min=self.PORTS_POOL_DEFAULT_DICT['ports_pool_min'])

        # check the original length of list of ports for new ns
        initial_ports_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        # create a pod to test the port pool increase by updated batch value
        pod_name1, pod1 = self.create_pod(namespace=namespace_name,
                                          labels={'type': 'demo'})

        # port number should increase by updated ports_pool_batch value
        updated_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        num_to_compare = updated_port_list_num - POOL_BATCH
        self.assertEqual(num_to_compare, initial_ports_num)

        # need to wait till ports_pool_update_frequency expires so new batch
        # creation could be executed in order to create additional pod
        time.sleep(int(
            self.PORTS_POOL_DEFAULT_DICT['ports_pool_update_frequency']))
        pod_name2, pod2 = self.create_pod(
            namespace=namespace_name,
            affinity={'podAffinity': consts.POD_AFFINITY})

        # the total number of ports should increase by 2 as there is only 1
        # port free and POOL_MIN=1, so new port batch will be created
        updated2_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        num_to_compare = updated2_port_list_num - 2 * POOL_BATCH
        self.assertEqual(num_to_compare, initial_ports_num)

        # create additional pod
        pod_name3, pod3 = self.create_pod(
            namespace=namespace_name,
            affinity={'podAffinity': consts.POD_AFFINITY})

        # the total number of ports should stay the same
        updated3_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        self.assertEqual(updated2_port_list_num, updated3_port_list_num)

        # check connectivity between pods
        pod_ip = self.get_pod_ip(pod_name1, namespace=namespace_name)
        cmd = [
            "/bin/sh", "-c", "ping -c 4 {dst_ip}>/dev/null ; echo $?".format(
                dst_ip=pod_ip)]
        self.assertEqual(self.exec_command_in_pod(
            pod_name2, cmd, namespace=namespace_name), '0')

        # delete all pods and make sure the number of new ports added during
        # pod creation is equal to POOL_MAX
        for pod_name in (pod_name1, pod_name2, pod_name3):
            self.delete_pod(pod_name, namespace=namespace_name)
        # timeout is needed as it takes time for ports to be deleted
        time.sleep(30)
        updated4_port_list_num = len(self.os_admin.ports_client.list_ports(
            fixed_ips='subnet_id=%s' % subnet_id)['ports'])
        LOG.info("Number of ports after pods deletion and timeout = {}".format(
            updated4_port_list_num))
        self.assertEqual(updated4_port_list_num - initial_ports_num, POOL_MAX)
