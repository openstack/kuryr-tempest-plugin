# install tempest plugin
function build_test_container {
    pushd "${DEST}/kuryr-tempest-plugin/test_container"

    # FIXME(dulek): Until https://github.com/containers/buildah/issues/1206 is
    #               resolved instead of podman we need to use buildah directly,
    #               hence this awful if clause.
    if [[ ${CONTAINER_ENGINE} == 'crio' ]]; then
        sudo buildah bud -t quay.io/kuryr/demo -f Dockerfile .
        sudo buildah bud -t quay.io/kuryr/sctp-demo -f \
            kuryr_sctp_demo/Dockerfile .
    else
        docker build -t quay.io/kuryr/demo . -f Dockerfile
        docker build -t quay.io/kuryr/sctp-demo . -f \
            kuryr_sctp_demo/Dockerfile
    fi
    popd
}

function install_kuryr_tempest_plugin {
    setup_dev_lib "kuryr-tempest-plugin"
}

if [[ "$1" == "stack" && "$2" == "extra" ]]; then
    echo_summary "Building kuryr/demo test container"
    build_test_container
elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
    # (gmann): Install Kuryr Tempest Plugin on the system only
    # if INSTALL_TEMPEST is True. Irrespective of plugin is
    # installed on system wide by this file or not, Tempest
    # and all enabled plugins will be installed and tested
    # via venv. INSTALL_TEMPEST is False on stable branches, as
    # master tempest or its plugins deps do not match
    # stable branch deps.
    if [[ "$INSTALL_TEMPEST" == "True" ]]; then
        echo_summary "Installing Kuryr Tempest Plugin"
        install_kuryr_tempest_plugin
    fi
fi
