# install tempest plugin
function install_kuryr_tempest_plugin {
    setup_dev_lib "kuryr-tempest-plugin"
}

if [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing Kuryr Tempest Plugin"
        install_kuryr_tempest_plugin
fi
