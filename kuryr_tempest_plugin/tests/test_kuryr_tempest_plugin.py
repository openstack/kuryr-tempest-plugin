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


"""
test_kuryr_tempest_plugin
----------------------------------

Tests for `kuryr_tempest_plugin` module.
"""

from tempest.lib import decorators

from kuryr_tempest_plugin.tests import base


class TestKuryr_tempest_plugin(base.BaseAdminKuryrTest):

    @decorators.idempotent_id('14990abd-76b4-476e-add2-321437d8cec5')
    def test_something(self):
        pass
