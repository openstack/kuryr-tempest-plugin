========================
Team and repository tags
========================

.. image:: https://governance.openstack.org/tc/badges/kuryr-tempest-plugin.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

.. Change things from this point on

============================
Tempest Integration of Kuryr
============================

Overview
========

This project defines a tempest plugin containing tests used to verify the
functionality of a kuryr installation. The plugin will automatically load
these tests into tempest.

For more information about Kuryr see:
https://docs.openstack.org/kuryr/latest/

For more information about Kuryr-kubernetes see:
https://docs.openstack.org/kuryr-kubernetes/latest/

For more information about Tempest plugins see:
https://docs.openstack.org/tempest/latest/plugin.html

* Free software: Apache license
* Documentation: https://docs.openstack.org/kuryr-tempest-plugin/latest/
* Source: https://opendev.org/openstack/kuryr-tempest-plugin
* Bugs: https://bugs.launchpad.net/kuryr

Installing
----------

Clone this repository and call from the repo::

    $ pip install -e .

Running the tests
-----------------

To verify the functionality of Kuryr by running tests from this plugin;
From the tempest repo, initialize stestr::

    $ stestr init

Then, to run all the tests from this plugin, call::

    $ tempest run -r 'kuryr_tempest_plugin.*'

To run a single test case, call with full path, for example::

    $ tempest run -r 'kuryr_tempest_plugin.tests.scenario.test_cross_ping.TestCrossPingScenario.test_vm_pod_ping*'

To retrieve a list of all tempest tests, run::

    $ tempest run -l
